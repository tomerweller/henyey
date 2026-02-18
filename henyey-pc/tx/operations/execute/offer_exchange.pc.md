## Pseudocode: crates/tx/src/operations/execute/offer_exchange.rs

"Offer exchange math helpers (v10+)."

### Data Structures

```
struct ConversionParams:
  source          // account initiating the conversion
  selling         // asset being sold
  buying          // asset being bought
  max_send        // maximum amount to send
  max_receive     // maximum amount to receive
  round           // rounding mode
  offer_trail     // accumulated claim atoms
  state           // ledger state
  context         // ledger context

enum RoundingType:
  Normal
  PathPaymentStrictSend
  PathPaymentStrictReceive

struct ExchangeResult:
  num_wheat_received
  num_sheep_send
  wheat_stays       // true if wheat side has remaining capacity
```

### Helper: big_multiply

```
function big_multiply(lhs, rhs):
  → lhs * rhs  // using 128-bit arithmetic, saturating
```

### Helper: big_divide_or_throw

```
function big_divide_or_throw(n, d, round):
  GUARD d <= 0            → InvalidPrice

  if round == Down:
    value = n / d         // truncate
  if round == Up:
    if n == 0:
      value = 0
    else:
      value = (n + d - 1) / d

  GUARD value > MAX_INT64 → Overflow
  → value
```

### Helper: calculate_offer_value

```
function calculate_offer_value(price_n, price_d, max_send, max_receive):
  send_value    = big_multiply(max_send, price_n)
  receive_value = big_multiply(max_receive, price_d)
  → min(send_value, receive_value)
```

### Helper: check_price_error_bound

```
function check_price_error_bound(price, wheat_receive, sheep_send, can_favor_wheat):
  err_n = 100 * price.n
  err_d = 100 * price.d

  lhs = big_multiply(wheat_receive, err_n)
  rhs = big_multiply(sheep_send, err_d)

  if can_favor_wheat AND rhs > lhs:
    → ok

  abs_diff = abs(lhs - rhs)
  cap = big_multiply(wheat_receive, price.n)

  GUARD abs_diff > cap → PriceError
  → ok
```

### exchange_v10_without_price_error_thresholds

```
function exchange_v10_without_price_error_thresholds(
    price, max_wheat_send, max_wheat_receive,
    max_sheep_send, max_sheep_receive, round):

  GUARD price.n <= 0 OR price.d <= 0 → InvalidPrice

  wheat_value = calculate_offer_value(price.n, price.d,
                  max_wheat_send, max_sheep_receive)
  sheep_value = calculate_offer_value(price.d, price.n,
                  max_sheep_send, max_wheat_receive)
  wheat_stays = wheat_value > sheep_value

  "--- Determine wheat_receive and sheep_send ---"

  if wheat_stays:
    if round == PathPaymentStrictSend:
      wheat_receive = big_divide_or_throw(
        min(wheat_value, sheep_value), price.n, Down)
      sheep_send = min(max_sheep_send, max_sheep_receive)

    else if price.n > price.d OR round == PathPaymentStrictReceive:
      wheat_receive = big_divide_or_throw(sheep_value, price.n, Down)
      sheep_send = big_divide_or_throw(
        wheat_receive * price.n, price.d, Up)

    else:
      sheep_send = big_divide_or_throw(sheep_value, price.d, Down)
      wheat_receive = big_divide_or_throw(
        sheep_send * price.d, price.n, Down)

  else if price.n > price.d:
    wheat_receive = big_divide_or_throw(wheat_value, price.n, Down)
    sheep_send = big_divide_or_throw(
      wheat_receive * price.n, price.d, Down)

  else:
    sheep_send = big_divide_or_throw(wheat_value, price.d, Down)
    wheat_receive = big_divide_or_throw(
      sheep_send * price.d, price.n, Up)

  "--- Validate bounds ---"

  GUARD wheat_receive < 0
    OR wheat_receive > min(max_wheat_receive, max_wheat_send)
    OR sheep_send < 0
    OR sheep_send > min(max_sheep_receive, max_sheep_send)
    → InvalidAmount

  → { wheat_receive, sheep_send, wheat_stays }
```

**Calls**: [big_divide_or_throw](#helper-big_divide_or_throw) | [calculate_offer_value](#helper-calculate_offer_value)

### adjust_offer_amount

```
function adjust_offer_amount(price, max_wheat_send, max_sheep_receive):
  res = exchange_v10(price, max_wheat_send, MAX_INT64,
          MAX_INT64, max_sheep_receive, Normal)
  → res.num_wheat_received
```

**Calls**: [exchange_v10](#exchange_v10)

### exchange_v10

```
function exchange_v10(price, max_wheat_send, max_wheat_receive,
                      max_sheep_send, max_sheep_receive, round):

  res = exchange_v10_without_price_error_thresholds(
          price, max_wheat_send, max_wheat_receive,
          max_sheep_send, max_sheep_receive, round)

  if res.wheat_received > 0 AND res.sheep_send > 0:
    wheat_value = big_multiply(res.wheat_received, price.n)
    sheep_value = big_multiply(res.sheep_send, price.d)

    GUARD wheat_stays AND sheep_value < wheat_value → InvalidAmount
    GUARD NOT wheat_stays AND sheep_value > wheat_value → InvalidAmount

    if round == Normal:
      if check_price_error_bound(price, wheat_received,
           sheep_send, false) fails:
        res.wheat_received = 0
        res.sheep_send = 0
    else:
      check_price_error_bound(price, wheat_received,
        sheep_send, true)   // propagate error

  else if round == PathPaymentStrictSend:
    "For strict send: when wheat_received=0 and sheep_send=0,"
    "the offer can't trade. When wheat_received=0 but sheep_send>0,"
    "rounding reduced output to 0. Let caller handle it."
    "NOTE: cross_offer_v10 must NOT apply balance changes when wheat_received=0."
    res.wheat_received = 0

  else:
    res.wheat_received = 0
    res.sheep_send = 0

  → res
```

**Calls**: [exchange_v10_without_price_error_thresholds](#exchange_v10_without_price_error_thresholds) | [check_price_error_bound](#helper-check_price_error_bound)

## Summary
| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 250    | 130        |
| Functions    | 7      | 7          |
