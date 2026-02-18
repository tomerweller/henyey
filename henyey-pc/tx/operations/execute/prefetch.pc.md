## Pseudocode: crates/tx/src/operations/execute/prefetch.rs

"Prefetch key collection for per-ledger batch loading."
"Matches stellar-core's insertLedgerKeysToPrefetch virtual method pattern."
"Only statically-determinable keys are included; keys that depend on
loaded state are handled separately in load_operation_accounts."

### Helper: asset_to_trustline_asset

```
function asset_to_trustline_asset(asset):
  if asset is Native:
    → null
  → TrustLineAsset from asset
```

### Helper: insert_asset_trustline

```
function insert_asset_trustline(keys, account_id, asset):
  tl_asset = asset_to_trustline_asset(asset)
  if tl_asset is not null:
    keys.add(trustline_key(account_id, tl_asset))
```

### prefetch_keys_create_account

```
function prefetch_keys_create_account(op, source, keys):
  keys.add(account_key(op.destination))
```

### prefetch_keys_payment

```
function prefetch_keys_payment(op, source, keys):
  dest = muxed_to_account_id(op.destination)
  keys.add(account_key(dest))
  insert_asset_trustline(keys, source, op.asset)
  insert_asset_trustline(keys, dest, op.asset)
```

**Calls:** [`muxed_to_account_id`](../../frame.pc.md) — REF: frame::muxed_to_account_id

### prefetch_keys_path_payment_strict_receive

```
function prefetch_keys_path_payment_strict_receive(
    op, source, keys):
  dest = muxed_to_account_id(op.destination)
  keys.add(account_key(dest))
  insert_asset_trustline(keys, source, op.send_asset)
  insert_asset_trustline(keys, dest, op.dest_asset)
```

### prefetch_keys_path_payment_strict_send

```
function prefetch_keys_path_payment_strict_send(
    op, source, keys):
  dest = muxed_to_account_id(op.destination)
  keys.add(account_key(dest))
  insert_asset_trustline(keys, source, op.send_asset)
  insert_asset_trustline(keys, dest, op.dest_asset)
```

### prefetch_keys_manage_sell_offer

```
function prefetch_keys_manage_sell_offer(op, source, keys):
  if op.offer_id != 0:
    keys.add(offer_key(source, op.offer_id))
  insert_asset_trustline(keys, source, op.selling)
  insert_asset_trustline(keys, source, op.buying)
```

### prefetch_keys_manage_buy_offer

```
function prefetch_keys_manage_buy_offer(op, source, keys):
  if op.offer_id != 0:
    keys.add(offer_key(source, op.offer_id))
  insert_asset_trustline(keys, source, op.selling)
  insert_asset_trustline(keys, source, op.buying)
```

### prefetch_keys_create_passive_sell_offer

```
function prefetch_keys_create_passive_sell_offer(
    op, source, keys):
  insert_asset_trustline(keys, source, op.selling)
  insert_asset_trustline(keys, source, op.buying)
```

### prefetch_keys_change_trust

```
function prefetch_keys_change_trust(op, source, keys):
  if op.line is CreditAlphanum4 or CreditAlphanum12:
    keys.add(trustline_key(source, op.line))
  if op.line is PoolShare:
    NOTE: "Pool share requires SHA-256 hash computation,
           skipped for prefetch — handled by
           load_operation_accounts instead."
```

### prefetch_keys_allow_trust

```
function prefetch_keys_allow_trust(op, source, keys):
  keys.add(account_key(op.trustor))
  tl_asset = build TrustLineAsset from op.asset code
    with issuer = source
  keys.add(trustline_key(op.trustor, tl_asset))
```

### prefetch_keys_set_trust_line_flags

```
function prefetch_keys_set_trust_line_flags(
    op, source, keys):
  keys.add(account_key(op.trustor))
  insert_asset_trustline(keys, op.trustor, op.asset)
```

### prefetch_keys_account_merge

```
function prefetch_keys_account_merge(dest, source, keys):
  dest_id = muxed_to_account_id(dest)
  keys.add(account_key(dest_id))
```

### prefetch_keys_manage_data

```
function prefetch_keys_manage_data(op, source, keys):
  keys.add(data_key(source, op.data_name))
```

### prefetch_keys_claim_claimable_balance

```
function prefetch_keys_claim_claimable_balance(
    op, source, keys):
  keys.add(claimable_balance_key(op.balance_id))
```

### prefetch_keys_create_claimable_balance

```
function prefetch_keys_create_claimable_balance(
    op, source, keys):
  insert_asset_trustline(keys, source, op.asset)
```

### prefetch_keys_clawback

```
function prefetch_keys_clawback(op, source, keys):
  from = muxed_to_account_id(op.from)
  insert_asset_trustline(keys, from, op.asset)
```

### prefetch_keys_clawback_claimable_balance

```
function prefetch_keys_clawback_claimable_balance(
    op, source, keys):
  keys.add(claimable_balance_key(op.balance_id))
```

### prefetch_keys_liquidity_pool_deposit

```
function prefetch_keys_liquidity_pool_deposit(
    op, source, keys):
  keys.add(liquidity_pool_key(op.liquidity_pool_id))
```

### prefetch_keys_liquidity_pool_withdraw

```
function prefetch_keys_liquidity_pool_withdraw(
    op, source, keys):
  keys.add(liquidity_pool_key(op.liquidity_pool_id))
```

### prefetch_keys_begin_sponsoring

```
function prefetch_keys_begin_sponsoring(op, source, keys):
  keys.add(account_key(op.sponsored_id))
```

### collect_prefetch_keys

"Central dispatcher that routes to per-operation functions."

```
function collect_prefetch_keys(op, source, keys):
  dispatch on op type:
    CreateAccount       → prefetch_keys_create_account
    Payment             → prefetch_keys_payment
    PathPaymentStrictReceive
                        → prefetch_keys_path_payment_strict_receive
    PathPaymentStrictSend
                        → prefetch_keys_path_payment_strict_send
    ManageSellOffer     → prefetch_keys_manage_sell_offer
    ManageBuyOffer      → prefetch_keys_manage_buy_offer
    CreatePassiveSellOffer
                        → prefetch_keys_create_passive_sell_offer
    ChangeTrust         → prefetch_keys_change_trust
    AllowTrust          → prefetch_keys_allow_trust
    SetTrustLineFlags   → prefetch_keys_set_trust_line_flags
    AccountMerge        → prefetch_keys_account_merge
    ManageData          → prefetch_keys_manage_data
    ClaimClaimableBalance
                        → prefetch_keys_claim_claimable_balance
    CreateClaimableBalance
                        → prefetch_keys_create_claimable_balance
    Clawback            → prefetch_keys_clawback
    ClawbackClaimableBalance
                        → prefetch_keys_clawback_claimable_balance
    LiquidityPoolDeposit
                        → prefetch_keys_liquidity_pool_deposit
    LiquidityPoolWithdraw
                        → prefetch_keys_liquidity_pool_withdraw
    BeginSponsoringFutureReserves
                        → prefetch_keys_begin_sponsoring

    "Soroban ops: empty — they use InMemorySorobanState;
     classic entries handled by load_soroban_footprint."
    InvokeHostFunction | ExtendFootprintTtl
      | RestoreFootprint → (no-op)

    "BumpSequence, Inflation, SetOptions, EndSponsoring,
     RevokeSponsorship: no statically-known keys."
    _                   → (no-op)
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 393    | 140        |
| Functions     | 22     | 22         |
