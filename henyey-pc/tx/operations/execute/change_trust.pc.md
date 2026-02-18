## Pseudocode: crates/tx/src/operations/execute/change_trust.rs

### execute_change_trust

```
function execute_change_trust(op, source, state, context):
  GUARD op.limit < 0                       → MALFORMED
  GUARD op.line is native                  → MALFORMED

  (maybe_asset, pool_params) = classify(op.line)
  is_pool_share = pool_params is some
  multiplier = 2 if is_pool_share else 1
  tl_asset = change_trust_asset_to_trust_line_asset(op.line)

  "Check not trusting self"
  if maybe_asset exists:
    issuer = get_asset_issuer(asset)
    if issuer exists:
      GUARD source == issuer               → MALFORMED

  GUARD source account not found           → error

  existing = state.get_trustline(source, tl_asset)

  --- Branch A: Removing trustline (limit == 0) ---
  if op.limit == 0:
    tl = state.get_trustline(source, tl_asset)
    GUARD tl not found                     → INVALID_LIMIT
    GUARD tl.balance > 0                   → INVALID_LIMIT
    GUARD trustline_liabilities(tl).buying > 0
                                           → INVALID_LIMIT

    if not pool_share:
      GUARD liquidity_pool_use_count(tl) != 0
                                           → CANNOT_DELETE

    if pool_share:
      GUARD manage_pool_on_deleted_trustline fails
                                           → CANNOT_DELETE
      decrement_pool_use_counts(state, source, pool_params)

    if trustline is sponsored:
      state.remove_entry_sponsorship_and_update_counts(
        trustline_key, source, multiplier)

    "Decrease sub-entries BEFORE deleting trustline.
     stellar-core records account STATE/UPDATED before
     trustline STATE/REMOVED."
    MUTATE source_account num_sub_entries -= multiplier

    "Flush ALL account changes before recording trustline
     deletion."
    state.flush_all_accounts()

    state.delete_trustline(source, tl_asset)

  --- Branch B: Updating existing trustline ---
  else if existing exists:
    current_balance = existing.balance
    current_buying_liab = trustline_liabilities(existing).buying
    GUARD op.limit < current_balance + current_buying_liab
                                           → INVALID_LIMIT

    if not pool_share:
      issuer = get_asset_issuer(asset)
      if issuer exists:
        GUARD issuer account not found     → NO_ISSUER

    MUTATE trustline limit = op.limit

  --- Branch C: Creating new trustline ---
  else:
    "Check issuer exists before subentry limit
     (matches stellar-core ordering)"
    if pool_share:
      validate_pool_share_trustlines(source, pool_params, state)
      increment_pool_use_counts(state, source, pool_params)
    else:
      issuer = get_asset_issuer(asset)
      if issuer exists:
        GUARD issuer account not found     → NO_ISSUER

    "Check subentries limit before creating trustline"
    GUARD source.num_sub_entries + multiplier
          > ACCOUNT_SUBENTRY_LIMIT
          → OP_TOO_MANY_SUBENTRIES

    --- Phase: Reserve check ---
    sponsor = state.active_sponsor_for(source)
    if sponsor exists:
      sponsor_account = state.get_account(sponsor)
      new_min_balance = minimum_balance_with_deltas(
        sponsor_account, protocol_version,
        sub_entry_delta=0, sponsoring_delta=multiplier,
        sponsored_delta=0)
      available = sponsor_account.balance
                - account_liabilities(sponsor).selling
      GUARD available < new_min_balance    → LOW_RESERVE
    else:
      new_min_balance = minimum_balance_for_account(
        source_account, protocol_version, multiplier)
      available = source.balance
                - account_liabilities(source).selling
      GUARD available < new_min_balance    → LOW_RESERVE

    trustline = TrustLineEntry {
      account_id: source,
      asset:      tl_asset,
      balance:    0,
      limit:      op.limit,
      flags:      build_trustline_flags(asset, state),
    }

    if sponsor exists:
      state.apply_entry_sponsorship(
        trustline_key, source, multiplier)
    state.create_trustline(trustline)

    if pool_share:
      manage_pool_on_new_trustline(state, tl_asset, pool_params)

    MUTATE source_account num_sub_entries += multiplier

  → SUCCESS
```

**Calls**: [account_liabilities](mod.pc.md#account_liabilities) | [trustline_liabilities](mod.pc.md#trustline_liabilities) | [active_sponsor_for](../../state.pc.md#active_sponsor_for)

---

### Helper: change_trust_asset_to_trust_line_asset

```
function change_trust_asset_to_trust_line_asset(asset):
  if asset is native:     → TrustLineAsset.Native
  if asset is credit4:    → TrustLineAsset.Credit4(asset)
  if asset is credit12:   → TrustLineAsset.Credit12(asset)
  if asset is pool_share:
    pool_id = sha256(xdr(params))
    → TrustLineAsset.PoolShare(pool_id)
```

### Helper: build_trustline_flags

```
CONST AUTH_REQUIRED_FLAG = 0x1
CONST AUTH_CLAWBACK_FLAG = 0x8
CONST TRUSTLINE_CLAWBACK_ENABLED_FLAG =
      TrustLineFlags.ClawbackEnabled

function build_trustline_flags(asset, state):
  if asset is none: → 0
  issuer = get_asset_issuer(asset)
  if issuer is none: → 0
  issuer_account = state.get_account(issuer)
  if not found: → 0

  flags = 0
  if issuer_account.flags & AUTH_REQUIRED_FLAG == 0:
    flags |= AUTHORIZED_FLAG
  if issuer_account.flags & AUTH_CLAWBACK_FLAG != 0:
    flags |= TRUSTLINE_CLAWBACK_ENABLED_FLAG
  → flags
```

### Helper: validate_pool_share_trustlines

```
function validate_pool_share_trustlines(source, params, state):
  validate_pool_asset_trustline(source, params.asset_a, state)
  validate_pool_asset_trustline(source, params.asset_b, state)

function validate_pool_asset_trustline(source, asset, state):
  if asset is native: → ok
  if source is issuer of asset: → ok
  trustline = state.get_trustline(source, asset)
  GUARD trustline not found
    → TRUST_LINE_MISSING
  GUARD not is_authorized_to_maintain_liabilities(tl.flags)
    → NOT_AUTH_MAINTAIN_LIABILITIES
```

### Helper: increment/decrement_pool_use_counts

```
function increment_pool_use_counts(state, source, params):
  increment_pool_use_count(state, source, params.asset_a)
  increment_pool_use_count(state, source, params.asset_b)

function increment_pool_use_count(state, source, asset):
  if asset is native: → done
  if source is issuer of asset: → done
  tl = state.get_trustline_mut(source, asset)
  v2 = ensure_trustline_ext_v2(tl)
  GUARD v2.liquidity_pool_use_count == INT32_MAX
    → error("overflow")
  MUTATE v2 liquidity_pool_use_count += 1

function decrement_pool_use_count(state, source, asset):
  if asset is native: → done
  if source is issuer of asset: → done
  tl = state.get_trustline_mut(source, asset)
  v2 = ensure_trustline_ext_v2(tl)
  if v2.liquidity_pool_use_count == 0: → done
  MUTATE v2 liquidity_pool_use_count -= 1
```

### Helper: liquidity_pool_use_count

```
function liquidity_pool_use_count(trustline):
  if trustline has v1.v2 extension:
    → v2.liquidity_pool_use_count
  → 0
```

### Helper: manage_pool_on_new_trustline

```
function manage_pool_on_new_trustline(state, tl_asset, params):
  pool_id = extract pool_id from tl_asset

  if pool already exists:
    MUTATE pool pool_shares_trust_line_count += 1
    → done

  "Create new pool entry"
  entry = LiquidityPoolEntry {
    liquidity_pool_id: pool_id,
    params:            params,
    reserve_a:         0,
    reserve_b:         0,
    total_pool_shares: 0,
    pool_shares_trust_line_count: 1,
  }
  state.create_liquidity_pool(entry)
```

### Helper: manage_pool_on_deleted_trustline

```
function manage_pool_on_deleted_trustline(state, tl_asset):
  pool_id = extract pool_id from tl_asset
  pool = state.get_liquidity_pool_mut(pool_id)
  GUARD pool not found  → false
  GUARD pool.pool_shares_trust_line_count == 0  → false
  MUTATE pool pool_shares_trust_line_count -= 1
  if pool.pool_shares_trust_line_count == 0:
    "Delete the pool (matching stellar-core behavior)"
    state.delete_liquidity_pool(pool_id)
  → true
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 527    | 165        |
| Functions     | 14     | 14         |
