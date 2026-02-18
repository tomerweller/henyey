## Pseudocode: crates/tx/src/operations/execute/mod.rs

### Constants

```
CONST ACCOUNT_SUBENTRY_LIMIT = 1000
CONST AUTHORIZED_FLAG = TrustLineFlags.Authorized
CONST AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG =
      TrustLineFlags.AuthorizedToMaintainLiabilities
```

### Helper: is_trustline_authorized

```
function is_trustline_authorized(flags):
  → flags & AUTHORIZED_FLAG != 0
```

### Helper: is_authorized_to_maintain_liabilities

```
function is_authorized_to_maintain_liabilities(flags):
  → flags & (AUTHORIZED_FLAG
           | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG) != 0
```

### Helper: issuer_for_asset

```
function issuer_for_asset(asset):
  if asset is native:   → none
  if asset is credit4:  → asset.issuer
  if asset is credit12: → asset.issuer
```

### Helper: account_liabilities

```
function account_liabilities(account):
  if account has v1 extension:
    → account.ext.v1.liabilities
  → { buying: 0, selling: 0 }
```

### Helper: trustline_liabilities

```
function trustline_liabilities(trustline):
  if trustline has v1 extension:
    → trustline.ext.v1.liabilities
  → { buying: 0, selling: 0 }
```

### Helper: ensure_account_liabilities

```
function ensure_account_liabilities(account):
  "Upgrades account ext to v1 if needed, returns
   mutable reference to liabilities"
  if account.ext is v0:
    MUTATE account ext = v1 { liabilities: {0, 0} }
  → account.ext.v1.liabilities
```

### Helper: ensure_trustline_liabilities

```
function ensure_trustline_liabilities(trustline):
  "Upgrades trustline ext to v1 if needed, returns
   mutable reference to liabilities"
  if trustline.ext is v0:
    MUTATE trustline ext = v1 { liabilities: {0, 0} }
  → trustline.ext.v1.liabilities
```

### add_account_balance

"Credit delta to an account's native balance. Returns false
 if overflow or buying liability constraint is violated."

```
function add_account_balance(account, delta):
  "Overflow-safe: INT64_MAX - balance < delta"
  GUARD INT64_MAX - account.balance < delta   → false
  new_balance = account.balance + delta
  "Buying liabilities: new_balance > INT64_MAX - buying"
  GUARD new_balance >
        INT64_MAX - account_liabilities(account).buying
                                                  → false
  MUTATE account balance = new_balance
  → true
```

### add_trustline_balance

"Credit delta to a trustline balance. Returns false if it
 exceeds the limit or buying liability constraint."

```
function add_trustline_balance(tl, delta):
  "Overflow-safe: limit - balance < delta"
  GUARD tl.limit - tl.balance < delta         → false
  new_balance = tl.balance + delta
  "Buying liabilities: new_balance > limit - buying"
  GUARD new_balance >
        tl.limit - trustline_liabilities(tl).buying
                                                  → false
  MUTATE tl balance = new_balance
  → true
```

### apply_balance_delta

"Apply a balance delta (positive or negative) to an account
 or trustline. Used by offer settlement — no liability checks."

```
function apply_balance_delta(account_id, asset, amount, state):
  if asset is native:
    account = state.get_account_mut(account_id)
    new_balance = account.balance + amount
    GUARD new_balance < 0  → error("balance underflow")
    MUTATE account balance = new_balance
    → done

  "Issuer can always send/receive their own asset"
  if issuer_for_asset(asset) == account_id:
    → done

  tl = state.get_trustline_mut(account_id, asset)
  new_balance = tl.balance + amount
  GUARD new_balance < 0 or new_balance > tl.limit
    → error("trustline balance out of bounds")
  MUTATE tl balance = new_balance
```

### Helper: is_asset_valid

"Check if an asset code is valid per stellar-core's
 isAssetValid()."
"Reference: stellar-core/src/util/types.cpp:146-211"

```
function is_asset_valid(asset):
  if asset is native:      → true
  if asset is credit4:
    code = asset.asset_code (4 bytes)
    zeros_started = false
    has_at_least_one_char = false
    for each byte in code:
      if byte == 0:
        zeros_started = true
      else if zeros_started:
        "zeros can only be trailing"
        → false
      else:
        GUARD byte > 0x7F or not alphanumeric  → false
        has_at_least_one_char = true
    → has_at_least_one_char

  if asset is credit12:
    code = asset.asset_code (12 bytes)
    zeros_started = false
    charcount = 0
    for each byte in code:
      if byte == 0:
        zeros_started = true
      else if zeros_started:
        → false
      else:
        GUARD byte > 0x7F or not alphanumeric  → false
        charcount += 1
    → charcount > 4
```

---

### Helper: rent_classification

```
function rent_classification(key):
  if key is ContractCode:     → (persistent=true, code=true)
  if key is ContractData:
    → (persistent = durability==Persistent, code=false)
  → (persistent=false, code=false)
```

### Helper: entry_size_for_rent_by_protocol

```
function entry_size_for_rent_by_protocol(
    protocol_version, entry, entry_xdr_size, cost_params):
  @version(<25):
    budget = build_budget_p24(cost_params)
    entry_p24 = convert_entry_to_p24(entry)
    → soroban_p24.entry_size_for_rent(budget, entry_p24,
                                       entry_xdr_size)
  @version(≥25):
    budget = build_budget_p25(cost_params)
    entry_p25 = convert_entry_to_p25(entry)
    → soroban_p25.entry_size_for_rent(budget, entry_p25,
                                       entry_xdr_size)
```

### Helper: rent_snapshot_for_keys

```
function rent_snapshot_for_keys(keys, state,
    protocol_version, cost_params):
  snapshots = []
  for each key in keys:
    entry = state.get_entry(key)
    if entry not found: continue
    entry_size = entry_size_for_rent_by_protocol(
      protocol_version, entry, xdr_len(entry), cost_params)
    key_hash = sha256(xdr(key))
    old_live_until = state.get_ttl(key_hash) or 0
    (is_persistent, is_code) = rent_classification(key)
    append { key, is_persistent, is_code,
             old_size_bytes: entry_size,
             old_live_until } to snapshots
  → snapshots
```

### Helper: rent_changes_from_snapshots

```
function rent_changes_from_snapshots(snapshots, state,
    protocol_version, cost_params):
  changes = []
  for each snapshot in snapshots:
    entry = state.get_entry(snapshot.key)
    if not found: continue
    new_size = entry_size_for_rent_by_protocol(...)
    new_live_until = state.get_ttl(key_hash) or
                     snapshot.old_live_until
    "Skip if no increase in either size or TTL"
    if new_live_until <= snapshot.old_live_until
       and new_size <= snapshot.old_size_bytes:
      continue
    append RentChange to changes
  → changes
```

### Helper: compute_rent_fee_by_protocol

```
function compute_rent_fee_by_protocol(
    protocol_version, rent_changes, config, ledger_seq):
  @version(<25):
    → soroban_p24.compute_rent_fee(changes, config, ledger_seq)
  @version(≥25):
    → soroban_p25.compute_rent_fee(changes, config, ledger_seq)
```

---

### execute_operation

```
function execute_operation(op, source_account_id, state, context):
  → delegate_to(execute_operation_with_soroban,
      op, source_account_id, ..., state, context,
      soroban_data=none, soroban_config=none,
      module_cache=none, hot_archive=none)
```

### execute_operation_with_soroban

```
function execute_operation_with_soroban(
    op, source_account_id, tx_source_id, tx_seq, op_index,
    state, context, soroban_data, soroban_config,
    module_cache, hot_archive):

  --- Phase: Resolve source ---
  op_source = op.source_account (if set)
              otherwise source_account_id

  "Check that the operation's source account exists.
   Matches stellar-core's OperationFrame::checkSourceAccount().
   If source was merged by a prior op, return opNO_ACCOUNT."
  GUARD source account not found  → OP_NO_ACCOUNT

  --- Phase: Dispatch by operation type ---
  CreateAccount       → execute_create_account(...)
    REF: create_account::execute_create_account
  Payment             → execute_payment(...)
    REF: payment::execute_payment
  ChangeTrust         → execute_change_trust(...)
    REF: change_trust::execute_change_trust
  ManageData          → execute_manage_data(...)
    REF: manage_data::execute_manage_data
  BumpSequence        → execute_bump_sequence(...)
    REF: bump_sequence::execute_bump_sequence
  AccountMerge        → execute_account_merge(...)
    REF: account_merge::execute_account_merge
  SetOptions          → execute_set_options(...)
    REF: set_options::execute_set_options

  --- Soroban operations ---
  InvokeHostFunction  → execute_invoke_host_function(...)
    REF: invoke_host_function::execute_invoke_host_function

  ExtendFootprintTtl:
    snapshots = rent_snapshot_for_keys(footprint_keys, ...)
    result = execute_extend_footprint_ttl(...)
      REF: extend_footprint_ttl::execute_extend_footprint_ttl
    if result is SUCCESS:
      rent_changes = rent_changes_from_snapshots(snapshots, ...)
      rent_fee = compute_rent_fee_by_protocol(...)
      attach SorobanOperationMeta { rent_fee }
    → result

  RestoreFootprint:
    "Track which entries ACTUALLY need restoration"
    for each key in footprint.read_write:
      ttl = state.get_ttl(key_hash)
      if ttl exists and ttl >= current_ledger:
        "Case 1: already live → skip"
        continue
      if ttl exists but expired:
        "Case 3: restore from live bucket list"
        take rent snapshot with actual old_size, old_ttl
      else:
        "Case 2: no TTL → check hot archive"
        if hot_archive has entry:
          take rent snapshot with old_size=0, old_ttl=0
          track as hot_archive_restore
    result = execute_restore_footprint(...)
      REF: restore_footprint::execute_restore_footprint
    if result is SUCCESS:
      rent_changes = rent_changes_from_snapshots(snapshots, ...)
      rent_fee = compute_rent_fee_by_protocol(...)
      attach SorobanOperationMeta { rent_fee,
        hot_archive_restores }
    → result

  --- DEX operations ---
  PathPaymentStrictReceive → execute_path_payment_strict_receive
  PathPaymentStrictSend    → execute_path_payment_strict_send
  ManageSellOffer          → execute_manage_sell_offer
  ManageBuyOffer           → execute_manage_buy_offer
  CreatePassiveSellOffer   → execute_create_passive_sell_offer
  AllowTrust               → execute_allow_trust
  Inflation                → execute_inflation

  --- Claimable balance operations ---
  CreateClaimableBalance   → execute_create_claimable_balance
  ClaimClaimableBalance    → execute_claim_claimable_balance

  --- Sponsorship operations ---
  BeginSponsoringFutureReserves → execute_begin_sponsoring
  EndSponsoringFutureReserves   → execute_end_sponsoring
  RevokeSponsorship             → execute_revoke_sponsorship

  --- Clawback operations ---
  Clawback                      → execute_clawback
  ClawbackClaimableBalance      → execute_clawback_cb

  --- Trust flags ---
  SetTrustLineFlags             → execute_set_trust_line_flags

  --- Liquidity pool operations ---
  LiquidityPoolDeposit          → execute_lp_deposit
  LiquidityPoolWithdraw         → execute_lp_withdraw
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 1020   | 220        |
| Functions     | 18     | 18         |
