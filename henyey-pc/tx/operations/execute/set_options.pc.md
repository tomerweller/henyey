## Pseudocode: crates/tx/src/operations/execute/set_options.rs

CONST MAX_SIGNERS = 20
CONST AUTH_REQUIRED_FLAG  = 0x1
CONST AUTH_REVOCABLE_FLAG = 0x2
CONST AUTH_IMMUTABLE_FLAG = 0x4
CONST AUTH_CLAWBACK_FLAG  = 0x8

### execute_set_options

"Modifies account settings: inflation destination, flags, master weight,
thresholds, home domain, and signers."

```
mask = MASK_ACCOUNT_FLAGS_V17

--- Phase: Flag validation ---
if set_flags present:
  GUARD set_flags has bits outside mask   → UNKNOWN_FLAG
if clear_flags present:
  GUARD clear_flags has bits outside mask → UNKNOWN_FLAG
if both set_flags and clear_flags present:
  GUARD set_flags & clear_flags != 0     → BAD_FLAGS

--- Phase: Threshold validation ---
if master_weight present:
  GUARD master_weight > 255 → THRESHOLD_OUT_OF_RANGE
if low_threshold present:
  GUARD low_threshold > 255 → THRESHOLD_OUT_OF_RANGE
if med_threshold present:
  GUARD med_threshold > 255 → THRESHOLD_OUT_OF_RANGE
if high_threshold present:
  GUARD high_threshold > 255 → THRESHOLD_OUT_OF_RANGE

--- Phase: Load source account ---
source_account = get_account(source)
GUARD source_account not found → error (source not found)

--- Phase: Immutability check ---
"If account is immutable, cannot set or clear auth flags"
if current_flags has AUTH_IMMUTABLE:
  set = set_flags or 0
  clear = clear_flags or 0
  GUARD (set | clear) & auth_flags_mask != 0 → CANT_CHANGE

--- Phase: Clawback requires revocable ---
"Check resulting flags after applying clear then set"
clear = clear_flags or 0
set = set_flags or 0
if clear != 0 or set != 0:
  new_flags = (current_flags & ~clear) | set
  GUARD new_flags has CLAWBACK but NOT REVOCABLE → AUTH_REVOCABLE_REQUIRED

--- Phase: Signer pre-computation ---
current_signer_count = source_account.signers.len
current_num_sub_entries = source_account.num_sub_entries
base_reserve = state.base_reserve()

if active_sponsor_for(source) exists:
  sponsor_id = active sponsor
  min_balance = minimum_balance(sponsor, +1 sponsoring)
  available = sponsor.balance - selling_liabilities
  sponsor_info = (sponsor_id, available, min_balance)
else:
  sponsor_info = nil

(num_sponsoring, num_sponsored) = sponsorship_counts(source_account)

--- Phase: Validate inflation destination ---
if inflation_dest present:
  GUARD inflation_dest != source AND account not found → INVALID_INFLATION

--- Phase: Apply mutations to account ---
MUTATE get_account_mut(source)

if inflation_dest present:
  MUTATE account.inflation_dest = inflation_dest

if clear_flags present:
  MUTATE account.flags &= ~clear_flags
if set_flags present:
  MUTATE account.flags |= set_flags

if master_weight present:
  MUTATE account.thresholds[0] = master_weight
if low_threshold present:
  MUTATE account.thresholds[1] = low_threshold
if med_threshold present:
  MUTATE account.thresholds[2] = med_threshold
if high_threshold present:
  MUTATE account.thresholds[3] = high_threshold

if home_domain present:
  MUTATE account.home_domain = home_domain

--- Phase: Signer management ---
if signer present:
  signer_key = signer.key
  weight = signer.weight
  GUARD weight > 255              → BAD_SIGNER
  GUARD signer_key == source key  → BAD_SIGNER
  if signer_key type is Ed25519SignedPayload:
    GUARD payload is empty        → BAD_SIGNER

  sponsor = sponsor_info.sponsor_id (if any)
  signers_vec = current signers list
  sponsoring_ids = current signer_sponsoring_ids list
  needs_sponsoring_ids = has_v2_ext OR sponsor exists

  "Pad or truncate sponsoring_ids to match signers_vec length"
  if needs_sponsoring_ids:
    align sponsoring_ids.len to signers_vec.len

  existing_pos = find signer_key in signers_vec

  --- Sub-phase: Remove signer (weight == 0) ---
  if weight == 0:
    if existing_pos found:
      if needs_sponsoring_ids AND signer was sponsored:
        num_sponsored_delta -= 1
        sponsor_delta = (old_sponsor, -1)
        remove sponsoring_ids[pos]
      remove signers_vec[pos]
      MUTATE account.num_sub_entries -= 1

  --- Sub-phase: Update existing signer weight ---
  else if existing_pos found:
    MUTATE signers_vec[pos].weight = weight

  --- Sub-phase: Add new signer ---
  else:
    GUARD current_signer_count >= MAX_SIGNERS  → TOO_MANY_SIGNERS
    GUARD num_sub_entries >= ACCOUNT_SUBENTRY_LIMIT → OpTooManySubentries

    "Reserve check"
    if sponsor_info exists:
      GUARD sponsor_balance < sponsor_min_balance → LOW_RESERVE
    else:
      effective = 2 + (num_sub_entries + 1) + num_sponsoring - num_sponsored
      new_min_balance = effective * base_reserve
      available = account.balance - selling_liabilities
      GUARD available < new_min_balance → LOW_RESERVE

    append new Signer(signer_key, weight) to signers_vec
    if needs_sponsoring_ids:
      append sponsor descriptor to sponsoring_ids
      sort (signers_vec, sponsoring_ids) together by signer key
    else:
      sort signers_vec by signer key

    if sponsor exists:
      num_sponsored_delta += 1
      sponsor_delta = (sponsor, +1)

    MUTATE account.num_sub_entries += 1

  --- Sub-phase: Persist signer changes ---
  if signers changed:
    MUTATE account.signers = signers_vec
    if needs_sponsoring_ids OR num_sponsored_delta != 0:
      ext_v2 = ensure_account_ext_v2(account)
      MUTATE ext_v2.num_sponsored += num_sponsored_delta
      if needs_sponsoring_ids:
        MUTATE ext_v2.signer_sponsoring_ids = sponsoring_ids

--- Phase: Update sponsor counts ---
if sponsor_delta exists:
  MUTATE state.update_num_sponsoring(sponsor_id, delta)

→ SUCCESS
```

**Calls:** [`state.active_sponsor_for`](../../../state.rs), [`state.minimum_balance_for_account_with_deltas`](../../../state.rs), [`state.update_num_sponsoring`](../../../state.rs), [`account_liabilities`](../mod.rs), [`ensure_account_ext_v2`](../../../state.rs)

---

### Helper: compare_signer_keys

```
if same key type:
  compare raw bytes of key content
else:
  compare by discriminant order:
    Ed25519(0) < PreAuthTx(1) < HashX(2) < Ed25519SignedPayload(3)
```

---

### Helper: sponsorship_counts_for_account_entry

```
if account.ext is V1 and ext is V2:
  → (num_sponsoring, num_sponsored)
else:
  → (0, 0)
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~437   | ~115       |
| Functions     | 5      | 4          |
