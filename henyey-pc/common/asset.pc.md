# Pseudocode: crates/common/src/asset.rs

"Asset utilities for validation, conversion, balance, price comparison, and bucket entry handling."

## Constants

```
CONST LIQUIDITY_POOL_FEE_V18 = 30  // 30 basis points = 0.3%
```

## ASCII Utilities

### is_ascii_alphanumeric

```
function is_ascii_alphanumeric(c) -> bool:
  -> c in 'a'..'z' OR 'A'..'Z' OR '0'..'9'
```

### is_ascii_non_control

```
function is_ascii_non_control(c) -> bool:
  -> c in 0x20..0x7E   // space through tilde
```

### to_ascii_lower

```
function to_ascii_lower(c) -> char:
  -> lowercase(c) if c in 'A'..'Z', else c
```

### is_string_valid

"Check string contains only printable ASCII non-control characters."

```
function is_string_valid(s) -> bool:
  -> all chars in s satisfy is_ascii_non_control
```

**Calls**: [is_ascii_non_control](#is_ascii_non_control)

### iequals

```
function iequals(a, b) -> bool:
  -> case-insensitive string equality
```

## Asset Code Conversion

### asset_code_to_str

"Read bytes until null or end of array."

```
function asset_code_to_str(code[N]) -> string:
  len = position of first 0x00 byte, or N
  -> string_from_bytes(code[0..len])
```

### str_to_asset_code

"Copy string into byte array, zero-pad remainder."

```
function str_to_asset_code(s) -> byte[N]:
  result = [0; N]
  n = min(N, len(s))
  copy s[0..n] into result[0..n]
  -> result
```

### asset_to_string

```
function asset_to_string(asset) -> string:
  if Native:          -> "XLM"
  if CreditAlphanum4: -> asset_code_to_str(asset.code)
  if CreditAlphanum12:-> asset_code_to_str(asset.code)
```

**Calls**: [asset_code_to_str](#asset_code_to_str)

## Asset Validation

### Helper: is_asset_code_valid

"All non-zero bytes must be ASCII alphanumeric, zeros only trailing."

```
function is_asset_code_valid(code, min_chars) -> bool:
  zeros_seen = false
  char_count = 0

  for each byte b in code:
    if b == 0:
      zeros_seen = true
    else if zeros_seen:
      -> false           // non-zero after zero = invalid
    else if b > 0x7F OR not is_ascii_alphanumeric(b):
      -> false
    else:
      char_count += 1

  -> char_count >= min_chars
```

**Calls**: [is_ascii_alphanumeric](#is_ascii_alphanumeric)

### is_asset_valid

```
function is_asset_valid(asset, ledger_version) -> bool:
  if Native:           -> true
  if CreditAlphanum4:  -> is_asset_code_valid(code, min_chars=1)
  if CreditAlphanum12: -> is_asset_code_valid(code, min_chars=5)
```

**Calls**: [is_asset_code_valid](#helper-is_asset_code_valid)

### is_trustline_asset_valid

```
function is_trustline_asset_valid(asset, ledger_version) -> bool:
  if Native:           -> true
  if CreditAlphanum4:  -> is_asset_code_valid(code, min_chars=1)
  if CreditAlphanum12: -> is_asset_code_valid(code, min_chars=5)
  if PoolShare:
    @version(>=18): -> true
    @version(<18):  -> false
```

**Calls**: [is_asset_code_valid](#helper-is_asset_code_valid) | [protocol_version_starts_from](protocol.pc.md#protocol_version_starts_from)

### is_change_trust_asset_valid

```
function is_change_trust_asset_valid(asset, ledger_version) -> bool:
  if Native:           -> true
  if CreditAlphanum4:  -> is_asset_code_valid(code, min_chars=1)
  if CreditAlphanum12: -> is_asset_code_valid(code, min_chars=5)
  if PoolShare(lp):
    @version(<18): -> false

    cp = lp.constant_product_params
    GUARD not is_asset_valid(cp.asset_a)  -> false
    GUARD not is_asset_valid(cp.asset_b)  -> false
    GUARD cp.asset_a >= cp.asset_b        -> false
    GUARD cp.fee != LIQUIDITY_POOL_FEE_V18 -> false
    -> true
```

**Calls**: [is_asset_valid](#is_asset_valid) | [protocol_version_is_before](protocol.pc.md#protocol_version_is_before)

### compare_asset

```
function compare_asset(first, second) -> bool:
  -> first == second
```

## Issuer Utilities

### get_issuer

```
function get_issuer(asset) -> AccountId:
  if CreditAlphanum4:  -> asset.issuer
  if CreditAlphanum12: -> asset.issuer
  if Native:           -> error(NoIssuer)
```

### get_trustline_asset_issuer

```
function get_trustline_asset_issuer(asset) -> AccountId:
  if CreditAlphanum4:  -> asset.issuer
  if CreditAlphanum12: -> asset.issuer
  if Native or PoolShare: -> error(NoIssuer)
```

### is_issuer

```
function is_issuer(account, asset) -> bool:
  issuer = get_issuer(asset)
  -> issuer exists AND issuer == account
```

**Calls**: [get_issuer](#get_issuer)

### is_trustline_asset_issuer

```
function is_trustline_asset_issuer(account, asset) -> bool:
  issuer = get_trustline_asset_issuer(asset)
  -> issuer exists AND issuer == account
```

**Calls**: [get_trustline_asset_issuer](#get_trustline_asset_issuer)

## Balance Utilities

### add_balance

"Add delta to balance with overflow and underflow checks."

```
function add_balance(balance, delta, max_balance) -> optional<i64>:
  ASSERT: balance >= 0
  ASSERT: max_balance >= 0

  if delta == 0:
    -> balance

  "Would go negative"
  GUARD delta < -balance                 -> none

  "Would exceed max"
  GUARD (max_balance - balance) < delta  -> none

  -> balance + delta
```

## Bucket Entry Utilities

### get_hot_archive_bucket_ledger_key

```
function get_hot_archive_bucket_ledger_key(entry) -> LedgerKey:
  if Archived:    -> ledger_entry_key(entry)
  if Live:        -> entry.key
  if Metaentry:   ASSERT: false "Tried to get key for METAENTRY"
```

**Calls**: [ledger_entry_key](#ledger_entry_key)

### get_bucket_ledger_key

```
function get_bucket_ledger_key(entry) -> LedgerKey:
  if Liveentry or Initentry: -> ledger_entry_key(entry)
  if Deadentry:              -> entry.key
  if Metaentry:              ASSERT: false "Tried to get key for METAENTRY"
```

**Calls**: [ledger_entry_key](#ledger_entry_key)

### ledger_entry_key

"Extract the LedgerKey from a LedgerEntry based on its data type."

```
function ledger_entry_key(entry) -> LedgerKey:
  data = entry.data
  if Account:          -> LedgerKey::Account { account_id }
  if Trustline:        -> LedgerKey::Trustline { account_id, asset }
  if Offer:            -> LedgerKey::Offer { seller_id, offer_id }
  if Data:             -> LedgerKey::Data { account_id, data_name }
  if ClaimableBalance: -> LedgerKey::ClaimableBalance { balance_id }
  if LiquidityPool:    -> LedgerKey::LiquidityPool { liquidity_pool_id }
  if ContractData:     -> LedgerKey::ContractData { contract, key, durability }
  if ContractCode:     -> LedgerKey::ContractCode { hash }
  if ConfigSetting:    -> LedgerKey::ConfigSetting { config_setting_id }
  if Ttl:              -> LedgerKey::Ttl { key_hash }
```

## Numeric Utilities

### round_down

"Round v down to largest multiple of m (m must be power of 2)."

```
function round_down(v, m) -> T:
  -> v AND NOT(m - 1)
```

### unsigned_to_signed_32

```
function unsigned_to_signed_32(v: u32) -> optional<i32>:
  GUARD v > I32_MAX  -> none
  -> v as i32
```

### unsigned_to_signed_64

```
function unsigned_to_signed_64(v: u64) -> optional<i64>:
  GUARD v > I64_MAX  -> none
  -> v as i64
```

### format_size

```
function format_size(size) -> string:
  CONST SUFFIXES = ["B", "KB", "MB", "GB"]

  dsize = size as double
  i = 0
  while dsize >= 1024 AND i < len(SUFFIXES) - 1:
    dsize /= 1024
    i += 1

  -> format("{:.2}{}", dsize, SUFFIXES[i])
```

## Price Comparison

### price_ge

"a.n/a.d >= b.n/b.d via cross-multiplication in 128-bit."

```
function price_ge(a, b) -> bool:
  ASSERT: a.n >= 0 AND a.d >= 0 AND b.n >= 0 AND b.d >= 0
  -> (a.n * b.d) >= (a.d * b.n)    // 128-bit arithmetic
```

### price_gt

```
function price_gt(a, b) -> bool:
  ASSERT: a.n >= 0 AND a.d >= 0 AND b.n >= 0 AND b.d >= 0
  -> (a.n * b.d) > (a.d * b.n)     // 128-bit arithmetic
```

### price_eq

```
function price_eq(a, b) -> bool:
  -> a == b
```

## Hash XOR Operations

### Hash256 XOR

```
function hash_xor(a, b) -> Hash256:
  for each byte i:
    result[i] = a[i] XOR b[i]
  -> Hash256(result)
```

### less_than_xored

"Compare (l XOR x) < (r XOR x) lexicographically."

```
function less_than_xored(l, r, x) -> bool:
  -> (l XOR x) < (r XOR x)
```

**Calls**: [hash_xor](#hash256-xor)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 395    | 200        |
| Functions     | 28     | 28         |
