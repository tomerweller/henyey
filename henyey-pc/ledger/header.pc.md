## Pseudocode: crates/ledger/src/header.rs

"Ledger header construction, hashing, and verification."
"Headers form the cryptographic backbone of the ledger chain."

```
CONST SKIP_LIST_SIZE = 4       // fixed by protocol
CONST SKIP_1         = 50      // skip list update intervals (from stellar-core)
CONST SKIP_2         = 5000
CONST SKIP_3         = 50000
CONST SKIP_4         = 500000
```

### <a id="compute_header_hash"></a>compute_header_hash

"SHA-256 digest of XDR-encoded header. Uniquely identifies the ledger."

```
FUNCTION compute_header_hash(header):
  xdr_bytes = XDR_encode(header)
  → SHA256(xdr_bytes)
```

### <a id="calculate_skip_values"></a>calculate_skip_values

"Update the skip list based on bucket_list_hash."
"Only updates when ledger_seq is divisible by SKIP_1 (50)."
"Algorithm from stellar-core BucketManager::calculateSkipValues"

```
FUNCTION calculate_skip_values(header):
  seq = header.ledger_seq

  if seq % SKIP_1 != 0:
    → return (no update)

  v = seq - SKIP_1
  if v > 0 AND v % SKIP_2 == 0:
    v2 = seq - SKIP_2 - SKIP_1
    if v2 > 0 AND v2 % SKIP_3 == 0:
      v3 = seq - SKIP_3 - SKIP_2 - SKIP_1
      if v3 > 0 AND v3 % SKIP_4 == 0:
        MUTATE header skip_list[3] = header.skip_list[2]
      MUTATE header skip_list[2] = header.skip_list[1]
    MUTATE header skip_list[1] = header.skip_list[0]
  MUTATE header skip_list[0] = header.bucket_list_hash
```

### skip_list_target_seq

"Calculate which historical ledger a skip list entry points to."

```
FUNCTION skip_list_target_seq(current_seq, skip_index):
  GUARD skip_index >= SKIP_LIST_SIZE  → None

  delta = case skip_index:
    0: 1                                     // previous ledger
    1: if current_seq % 4  == 0 then 4  else (current_seq % 4)
    2: if current_seq % 16 == 0 then 16 else (current_seq % 16)
    3: if current_seq % 64 == 0 then 64 else (current_seq % 64)

  if current_seq >= delta:
    → current_seq - delta
  else:
    → None
```

### verify_header_chain

"Verify cryptographic chain integrity between consecutive ledgers."

```
FUNCTION verify_header_chain(prev_header, prev_header_hash, current_header):
  expected_seq = prev_header.ledger_seq + 1

  GUARD current_header.ledger_seq != expected_seq
    → InvalidSequence { expected_seq, current_header.ledger_seq }

  current_prev_hash = current_header.previous_ledger_hash

  GUARD current_prev_hash != prev_header_hash
    → HashMismatch { prev_header_hash, current_prev_hash }

  → OK
```

### verify_skip_list

"Verify each non-zero skip list entry against historical headers."

```
FUNCTION verify_skip_list(header, get_header_at_seq):
  for each (i, skip_hash) in header.skip_list:
    if skip_hash is zero:
      continue

    target_seq = skip_list_target_seq(header.ledger_seq, i)
    if target_seq exists:
      expected_hash = get_header_at_seq(target_seq)
      if expected_hash exists:
        GUARD skip_hash != expected_hash
          → InvalidHeaderChain("skip list entry i mismatch")

  → OK
```

**Calls**: [skip_list_target_seq](#skip_list_target_seq)

### <a id="create_next_header"></a>create_next_header

"Construct next ledger header inheriting fields from previous."
"Must be called after setting bucket_list_hash but before computing header hash."

```
FUNCTION create_next_header(prev_header, prev_header_hash,
    close_time, tx_set_hash, bucket_list_hash,
    tx_set_result_hash, total_coins, fee_pool,
    inflation_seq, stellar_value_ext):

  new_seq = prev_header.ledger_seq + 1

  header = new LedgerHeader:
    ledger_version      = prev_header.ledger_version
    previous_ledger_hash = prev_header_hash
    scp_value:
      tx_set_hash  = tx_set_hash
      close_time   = close_time
      upgrades     = []
      ext          = stellar_value_ext
    tx_set_result_hash  = tx_set_result_hash
    bucket_list_hash    = bucket_list_hash
    ledger_seq          = new_seq
    total_coins         = total_coins
    fee_pool            = fee_pool
    inflation_seq       = inflation_seq
    id_pool             = prev_header.id_pool
    base_fee            = prev_header.base_fee
    base_reserve        = prev_header.base_reserve
    max_tx_set_size     = prev_header.max_tx_set_size
    skip_list           = prev_header.skip_list
    ext                 = V0

  calculate_skip_values(header)
  → header
```

NOTE: base_fee, base_reserve, max_tx_set_size are inherited and can be
modified by protocol upgrades after header creation.

**Calls**: [calculate_skip_values](#calculate_skip_values)

### close_time

```
FUNCTION close_time(header):
  → header.scp_value.close_time
```

### protocol_version

```
FUNCTION protocol_version(header):
  → header.ledger_version
```

### is_before_protocol_version

```
FUNCTION is_before_protocol_version(header, version):
  → header.ledger_version < version
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 336    | 93         |
| Functions     | 8      | 8          |
