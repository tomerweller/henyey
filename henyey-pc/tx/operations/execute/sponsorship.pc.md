## Pseudocode: crates/tx/src/operations/execute/sponsorship.rs

### execute_begin_sponsoring_future_reserves

"This operation marks the beginning of a sponsorship relationship where
the source account will pay reserves for entries created by the sponsored account."

"Note: The sponsored account does NOT need to exist at this point - it may be
created by a later operation in the same transaction (e.g., CreateAccount)."

```
GUARD source account not found   → MALFORMED
GUARD source == op.sponsored_id  → MALFORMED
GUARD sponsored_id already sponsored → ALREADY_SPONSORED
GUARD source is sponsored OR sponsored_id is sponsoring → RECURSIVE

MUTATE state push_sponsorship(source, op.sponsored_id)

→ SUCCESS
```

**Calls:** [`state.push_sponsorship`](../../../state.rs)

---

### execute_end_sponsoring_future_reserves

"This operation ends a sponsorship relationship that was begun with
BeginSponsoringFutureReserves."

```
GUARD source account not found         → NOT_SPONSORED
GUARD remove_sponsorship_for(source) fails → NOT_SPONSORED

→ SUCCESS
```

**Calls:** [`state.remove_sponsorship_for`](../../../state.rs)

---

### execute_revoke_sponsorship

"This operation revokes sponsorship of a ledger entry, transferring
the reserve responsibility back to the entry owner."

```
GUARD source account not found → NOT_SPONSOR

--- Branch: LedgerEntry ---
  GUARD entry does not exist → DOES_NOT_EXIST

  "Determine owner and reserve multiplier"
  owner_id, multiplier = entry type switch:
    Account       → (account_id, 2)
    Trustline     → (account_id, 2 if PoolShare else 1)
    Offer         → (seller_id, 1)
    Data          → (account_id, 1)
    ClaimableBalance →
      GUARD no entry sponsor  → MALFORMED
      (sponsor, claimants.len)
    other         → MALFORMED

  current_sponsor = entry_sponsor(ledger_key)
  was_sponsored = current_sponsor exists

  "Authorization check"
  if was_sponsored:
    GUARD current_sponsor != source → NOT_SPONSOR
  else:
    GUARD owner_id != source        → NOT_SPONSOR

  new_sponsor = active_sponsor_for(source)
  will_be_sponsored = new_sponsor exists AND new_sponsor != owner_id

  GUARD ClaimableBalance AND NOT will_be_sponsored → ONLY_TRANSFERABLE

  "Phase: Transfer sponsorship (was → will)"
  if was_sponsored AND will_be_sponsored:
    new_min = minimum_balance(new_sponsor, +multiplier sponsoring)
    available = new_sponsor.balance - selling_liabilities
    GUARD available < new_min → LOW_RESERVE

    MUTATE old_sponsor  num_sponsoring -= multiplier
    MUTATE new_sponsor  num_sponsoring += multiplier
    MUTATE entry_sponsor = new_sponsor

  "Phase: Remove sponsorship (was, not will)"
  else if was_sponsored AND NOT will_be_sponsored:
    if owner account exists:
      new_min = minimum_balance(owner, -multiplier sponsored)
      available = owner.balance - selling_liabilities
      GUARD available < new_min → LOW_RESERVE
    if ClaimableBalance:
      remove_entry_sponsorship_with_sponsor_counts(key, nil, multiplier)
    else:
      remove_entry_sponsorship_and_update_counts(key, owner, multiplier)

  "Phase: Add sponsorship (not was, will)"
  else if NOT was_sponsored AND will_be_sponsored:
    new_min = minimum_balance(new_sponsor, +multiplier sponsoring)
    available = new_sponsor.balance - selling_liabilities
    GUARD available < new_min → LOW_RESERVE

    apply_entry_sponsorship_with_sponsor(key, new_sponsor, owner, multiplier)

  if sponsorship changed:
    update_entry_after_sponsorship(state, ledger_key)

  → SUCCESS

--- Branch: Signer ---
  GUARD account does not exist              → DOES_NOT_EXIST
  GUARD signer not found in account.signers → DOES_NOT_EXIST

  owner_id = signer_key.account_id
  current_sponsor = current_signer_sponsor(account, pos)
  was_sponsored = current_sponsor exists

  "Authorization check"
  if was_sponsored:
    GUARD current_sponsor != source → NOT_SPONSOR
  else:
    GUARD owner_id != source        → NOT_SPONSOR

  new_sponsor = active_sponsor_for(source)
  will_be_sponsored = new_sponsor exists AND new_sponsor != owner_id

  "Phase: Transfer signer sponsorship"
  if was_sponsored AND will_be_sponsored:
    new_min = minimum_balance(new_sponsor, +1 sponsoring)
    available = new_sponsor.balance - selling_liabilities
    GUARD available < new_min → LOW_RESERVE

    MUTATE old_sponsor  num_sponsoring -= 1
    MUTATE new_sponsor  num_sponsoring += 1
    set_signer_sponsor(state, owner, pos, new_sponsor)

  "Phase: Remove signer sponsorship"
  else if was_sponsored AND NOT will_be_sponsored:
    if owner account exists:
      new_min = minimum_balance(owner, -1 sponsored)
      available = owner.balance - selling_liabilities
      GUARD available < new_min → LOW_RESERVE

    MUTATE old_sponsor  num_sponsoring -= 1
    MUTATE owner        num_sponsored  -= 1
    set_signer_sponsor(state, owner, pos, nil)

  "Phase: Add signer sponsorship"
  else if NOT was_sponsored AND will_be_sponsored:
    new_min = minimum_balance(new_sponsor, +1 sponsoring)
    available = new_sponsor.balance - selling_liabilities
    GUARD available < new_min → LOW_RESERVE

    MUTATE new_sponsor  num_sponsoring += 1
    MUTATE owner        num_sponsored  += 1
    set_signer_sponsor(state, owner, pos, new_sponsor)

  → SUCCESS
```

**Calls:** [`state.entry_sponsor`](../../../state.rs), [`state.active_sponsor_for`](../../../state.rs), [`state.minimum_balance_for_account_with_deltas`](../../../state.rs), [`state.update_num_sponsoring`](../../../state.rs), [`state.update_num_sponsored`](../../../state.rs), [`account_liabilities`](../mod.rs)

---

### Helper: update_entry_after_sponsorship

```
"Touch the entry to mark it dirty after sponsorship change"
entry type switch:
  Account          → get_account_mut(account_id)
  Trustline        → get_trustline_mut(account_id, asset)
  Offer            → get_offer_mut(seller_id, offer_id)
  Data             → get_data_mut(account_id, name)
  ClaimableBalance → get_claimable_balance_mut(balance_id)
  other            → no-op
```

---

### Helper: current_signer_sponsor

```
if account.ext is V1 and ext is V2:
  → signer_sponsoring_ids[pos] (if present and non-nil)
else:
  → nil
```

---

### Helper: set_signer_sponsor

```
account = get_account_mut(account_id)
ext_v2 = ensure_account_ext_v2(account)
GUARD sponsoring_ids.len <= pos → error "out of range"
MUTATE sponsoring_ids[pos] = sponsor
MUTATE ext_v2.signer_sponsoring_ids = sponsoring_ids
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~490   | ~120       |
| Functions     | 8      | 6          |
