## Pseudocode: crates/tx/src/operations/execute/claimable_balance.rs

### execute_create_claimable_balance

```
function execute_create_claimable_balance(
    op, source, tx_source, tx_seq, op_index, state, context):

  --- Phase: Validation ---
  GUARD op.claimants is empty              → MALFORMED
  GUARD op.amount <= 0                     → MALFORMED

  "Check for duplicate claimants and validate predicates"
  destinations = {}
  for each claimant in op.claimants:
    GUARD claimant.destination already in destinations
                                           → MALFORMED
    add claimant.destination to destinations
    GUARD not validate_claim_predicate(claimant.predicate, depth=1)
                                           → MALFORMED

  "stellar-core calls loadSourceAccount which records access"
  state.record_account_access(source)
  account = state.get_account(source)
  GUARD account not found                  → UNDERFUNDED

  issuer = asset_issuer(op.asset)
  sponsor = state.active_sponsor_for(source) or source
  sponsorship_multiplier = op.claimants.length

  --- Phase: Balance check ---
  "stellar-core order:
   1. Check available balance (UNDERFUNDED) - before deducting
   2. Deduct balance
   3. createEntryWithPossibleSponsorship (LOW_RESERVE)
   Must check UNDERFUNDED before LOW_RESERVE."

  if op.asset is native:
    "NOTE: stellar-core getAvailableBalance() uses getMinBalance()
     which does NOT include the sponsorship for the new claimable
     balance."
    min_balance = minimum_balance_for_account(
      account, protocol_version, delta=0)
    available = (account.balance - min_balance)
              - account_liabilities(account).selling
      REF: mod::account_liabilities
    GUARD available < op.amount            → UNDERFUNDED
  else:
    if source is not issuer:
      tl = state.get_trustline(source, op.asset)
      GUARD tl not found                   → NO_TRUST
      GUARD not is_trustline_authorized(tl.flags)
                                           → NOT_AUTHORIZED
      available = tl.balance
                - trustline_liabilities(tl).selling
      GUARD available < op.amount          → UNDERFUNDED

  --- Phase: Deduct balance ---
  balance_id = generate_claimable_balance_id(
    tx_source, tx_seq, op_index)

  if op.asset is native:
    MUTATE source_account balance -= op.amount
  else:
    if source is not issuer:
      MUTATE trustline balance -= op.amount

  --- Phase: Sponsor reserve check ---
  "NOW check sponsor's reserve (matches stellar-core
   createEntryWithPossibleSponsorship — AFTER balance deduction)"
  sponsor_account = state.get_account(sponsor)
  sponsor_min_balance = minimum_balance_with_deltas(
    sponsor_account, protocol_version,
    sub_entry_delta=0,
    sponsoring_delta=sponsorship_multiplier,
    sponsored_delta=0)
  available = sponsor_account.balance
            - account_liabilities(sponsor_account).selling
  GUARD available < sponsor_min_balance    → LOW_RESERVE

  --- Phase: Build entry ---
  claimable_flags = 0
  if issuer exists:
    clawback_enabled =
      (if issuer == source: account.flags & CLAWBACK_ENABLED
       else: trustline_flags & TRUSTLINE_CLAWBACK_ENABLED)
    if clawback_enabled:
      claimable_flags |= CB_CLAWBACK_ENABLED

  "Convert relative time predicates into absolute times"
  claimants = copy of op.claimants
  for each claimant in claimants:
    update_predicate_for_apply(claimant.predicate, close_time)

  entry = ClaimableBalanceEntry {
    balance_id, claimants, asset: op.asset,
    amount: op.amount, flags: claimable_flags
  }

  state.apply_entry_sponsorship_with_sponsor(
    balance_key, sponsor, none, sponsorship_multiplier)
  state.create_claimable_balance(entry)

  → SUCCESS(balance_id)
```

**Calls**: [account_liabilities](mod.pc.md#account_liabilities) | [trustline_liabilities](mod.pc.md#trustline_liabilities) | [is_trustline_authorized](mod.pc.md#is_trustline_authorized) | [active_sponsor_for](../../state.pc.md#active_sponsor_for)

---

### execute_claim_claimable_balance

```
function execute_claim_claimable_balance(
    op, source, state, context):

  entry = state.get_claimable_balance(op.balance_id)
  GUARD entry not found                    → DOES_NOT_EXIST

  "Check if source is a valid claimant"
  is_valid = any claimant where
    claimant.destination == source
    AND check_predicate(claimant.predicate, context)
  GUARD not is_valid                       → CANNOT_CLAIM

  "Use mutable access to mirror stellar-core loadSourceAccount"
  GUARD source account not found           → CANNOT_CLAIM

  --- Phase: Transfer balance ---
  if entry.asset is native:
    GUARD not add_account_balance(source_account, entry.amount)
                                           → LINE_FULL
      REF: mod::add_account_balance
  else:
    issuer = asset_issuer(entry.asset)
    if source == issuer:
      "Issuer claiming own asset: no trustline update needed
       (tokens returned to issuer)"
    else:
      tl = state.get_trustline_mut(source, entry.asset)
      GUARD tl not found                   → NO_TRUST
      GUARD not is_trustline_authorized(tl.flags)
                                           → NOT_AUTHORIZED
      GUARD not add_trustline_balance(tl, entry.amount)
                                           → LINE_FULL
        REF: mod::add_trustline_balance

  --- Phase: Delete claimable balance ---
  sponsorship_multiplier = entry.claimants.length
  sponsor = state.entry_sponsor(balance_key)
  state.delete_claimable_balance(op.balance_id)
  if sponsor exists:
    state.update_num_sponsoring(sponsor,
                                -sponsorship_multiplier)

  → SUCCESS
```

**Calls**: [add_account_balance](mod.pc.md#add_account_balance) | [add_trustline_balance](mod.pc.md#add_trustline_balance) | [is_trustline_authorized](mod.pc.md#is_trustline_authorized)

---

### Helper: generate_claimable_balance_id

```
function generate_claimable_balance_id(tx_source, tx_seq, op_index):
  preimage = HashIdPreimage.OpId {
    source_account: tx_source,
    seq_num:        tx_seq,
    op_num:         op_index,
  }
  → ClaimableBalanceId.V0( sha256(xdr(preimage)) )
```

### Helper: check_predicate

```
function check_predicate(predicate, context):
  Unconditional           → true
  And(left, right)        → len==2 AND all satisfied
  Or(left, right)         → len==2 AND any satisfied
  Not(inner)              → inner exists AND not satisfied
  BeforeAbsoluteTime(t)   → context.close_time < t
  BeforeRelativeTime(_)   → false
```

### Helper: validate_claim_predicate

```
function validate_claim_predicate(predicate, depth):
  GUARD depth > 4                          → false
  Unconditional           → true
  And(left, right)        → len==2 AND both valid at depth+1
  Or(left, right)         → len==2 AND both valid at depth+1
  Not(inner)              → inner exists AND valid at depth+1
  BeforeAbsoluteTime(t)   → t >= 0
  BeforeRelativeTime(t)   → t >= 0
```

### Helper: update_predicate_for_apply

"Convert relative time predicates to absolute at apply time."

```
function update_predicate_for_apply(predicate, close_time):
  And(left, right):
    recurse on both children
  Or(left, right):
    recurse on both children
  Not(inner):
    recurse on inner
  BeforeRelativeTime(relative):
    absolute = close_time + relative
    "cap at INT64_MAX if overflow"
    predicate = BeforeAbsoluteTime(absolute)
  BeforeAbsoluteTime, Unconditional:
    "no change"
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 521    | 145        |
| Functions     | 7      | 7          |
