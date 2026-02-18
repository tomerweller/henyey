## Pseudocode: crates/tx/src/operations/execute/trust_flags.rs

"Trust line flag operations execution."
"This module implements the execution logic for:"
"- AllowTrust (deprecated, but still supported)"
"- SetTrustLineFlags"

```
CONST AUTH_REVOCABLE_FLAG = 0x2
CONST AUTHORIZED_FLAG = 0x1
CONST AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG = 0x2  // from parent module
CONST TRUSTLINE_AUTH_FLAGS = AUTHORIZED_FLAG | AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG
```

---

### execute_allow_trust

"This operation sets the authorized flag on a trustline. It has been"
"deprecated in favor of SetTrustLineFlags but is still supported."

```
function execute_allow_trust(op, source, state, context):

  --- Phase 1: Issuer validation ---
  "stellar-core loads the source account in a nested LedgerTxn (ltxSource)"
  "that gets rolled back, so the source account access is NOT recorded in"
  "the transaction changes. We use get_account() (read-only) to match."
  issuer = state.get_account(source)
  GUARD issuer is null → Malformed

  GUARD op.trustor == source → SelfNotAllowed

  --- Phase 2: AUTH_REVOCABLE check (before trustline load) ---
  "Cannot fully deauthorize (authorize == 0) without AUTH_REVOCABLE"
  auth_revocable = issuer.flags & AUTH_REVOCABLE_FLAG != 0
  GUARD NOT auth_revocable AND op.authorize == 0 → CantRevoke

  --- Phase 3: Build asset from asset code ---
  if op.asset is CreditAlphanum4:
    asset = CreditAlphanum4(op.asset.code, source)
  else if op.asset is CreditAlphanum12:
    asset = CreditAlphanum12(op.asset.code, source)

  --- Phase 4: Load trustline ---
  trustline = state.get_trustline(op.trustor, asset)
  GUARD trustline is null → NoTrustLine

  --- Phase 5: Calculate new flags ---
  new_flags = trustline.flags
  new_flags &= ~TRUSTLINE_AUTH_FLAGS     // clear auth flags
  new_flags |= op.authorize              // set based on authorize value

  --- Phase 6: Second CantRevoke check ---
  "Cannot downgrade from AUTHORIZED to"
  "AUTHORIZED_TO_MAINTAIN_LIABILITIES without AUTH_REVOCABLE"
  was_authorized = trustline.flags & AUTHORIZED_FLAG != 0
  setting_maintain = new_flags & AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG != 0
  GUARD NOT auth_revocable AND was_authorized AND setting_maintain → CantRevoke

  --- Phase 7: Remove offers if revoking liabilities ---
  "when going from authorized-to-maintain-liabilities"
  "to not-authorized-to-maintain-liabilities, remove all offers"
  was_auth_maintain = is_authorized_to_maintain_liabilities(trustline.flags)
  will_auth_maintain = is_authorized_to_maintain_liabilities(new_flags)

  if was_auth_maintain AND NOT will_auth_maintain:
    remove_offers_with_cleanup(state, op.trustor, asset)

  --- Phase 8: Update trustline ---
  MUTATE trustline flags = new_flags

  → Success
```

**Calls:** [is_authorized_to_maintain_liabilities](../execute.pc.md#helper-is_authorized_to_maintain_liabilities), [remove_offers_with_cleanup](#helper-remove_offers_with_cleanup)

---

### execute_set_trust_line_flags

"This operation sets or clears specific flags on a trustline."

```
function execute_set_trust_line_flags(op, source, state, context):

  --- Phase 1: Source account validation ---
  "stellar-core loads the source account in a nested LedgerTxn (ltxSource)"
  "that gets rolled back, so the source account access is NOT recorded."
  source_account = state.get_account(source)
  GUARD source_account is null → Malformed

  --- Phase 2: Issuer check ---
  GUARD op.asset is Native → Malformed

  issuer = issuer_of(op.asset)
  GUARD issuer != source → Malformed

  --- Phase 3: AUTH_REVOCABLE check (before trustline load) ---
  "stellar-core checks isAuthRevocationValid() before loading the trustline,"
  "so CantRevoke takes priority over NoTrustLine when both conditions are true."
  "If AUTH_REVOCABLE is not set on the issuer account, the following transitions"
  "are not allowed:"
  "1. AUTHORIZED_FLAG -> AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG"
  "2. AUTHORIZED_FLAG -> 0"
  "3. AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG -> 0"
  auth_revocable = source_account.flags & AUTH_REVOCABLE_FLAG != 0
  if NOT auth_revocable:
    clearing_any_auth = (op.clear_flags & TRUSTLINE_AUTH_FLAGS) != 0
    setting_authorized = (op.set_flags & AUTHORIZED_FLAG) != 0
    GUARD clearing_any_auth AND NOT setting_authorized → CantRevoke

  --- Phase 4: Load trustline ---
  trustline = state.get_trustline(op.trustor, op.asset)
  GUARD trustline is null → NoTrustLine

  --- Phase 5: Validate flag combination ---
  GUARD (op.set_flags has AUTHORIZED_FLAG)
    AND (op.set_flags has AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG)
    → Malformed

  GUARD (op.set_flags & op.clear_flags) != 0 → Malformed

  --- Phase 6: Calculate new flags ---
  new_flags = trustline.flags
  new_flags &= ~op.clear_flags     // clear first
  new_flags |= op.set_flags        // then set

  "cannot have both auth flags set"
  GUARD NOT is_trust_line_flag_auth_valid(new_flags) → InvalidState

  --- Phase 7: Remove offers if revoking liabilities ---
  "when going from authorized-to-maintain-liabilities"
  "to not-authorized-to-maintain-liabilities, remove all offers"
  was_auth_maintain = is_authorized_to_maintain_liabilities(trustline.flags)
  will_auth_maintain = is_authorized_to_maintain_liabilities(new_flags)

  if was_auth_maintain AND NOT will_auth_maintain:
    remove_offers_with_cleanup(state, op.trustor, op.asset)
    NOTE: Pool share trustline redemption is not yet implemented.

  --- Phase 8: Update trustline ---
  MUTATE trustline flags = new_flags

  → Success
```

**Calls:** [is_authorized_to_maintain_liabilities](../execute.pc.md#helper-is_authorized_to_maintain_liabilities), [is_trust_line_flag_auth_valid](#helper-is_trust_line_flag_auth_valid), [remove_offers_with_cleanup](#helper-remove_offers_with_cleanup)

---

### Helper: is_trust_line_flag_auth_valid

"Both AUTHORIZED_FLAG and AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG cannot"
"be set at the same time."

```
function is_trust_line_flag_auth_valid(flags):
  → (flags & TRUSTLINE_AUTH_FLAGS) != TRUSTLINE_AUTH_FLAGS
```

---

### Helper: remove_offers_with_cleanup

"Remove offers by account and asset with full cleanup."
"This handles:"
"- Releasing liabilities on trustlines/accounts"
"- Decrementing num_sub_entries on the seller account"
"- Updating sponsorship counts if the offer was sponsored"

```
function remove_offers_with_cleanup(state, account_id, asset):
  removed_offers = state.remove_offers_by_account_and_asset(
                     account_id, asset)

  for each offer in removed_offers:
    release_offer_liabilities(state, offer)

    ledger_key = LedgerKey::Offer(offer.seller_id, offer.offer_id)
    sponsor = state.entry_sponsor(ledger_key)
    if sponsor exists:
      MUTATE sponsor num_sponsoring -= 1
      MUTATE offer.seller_id num_sponsored -= 1

    MUTATE offer.seller_id num_sub_entries -= 1
      (clamped to 0)
```

**Calls:** [release_offer_liabilities](#helper-release_offer_liabilities)

---

### Helper: release_offer_liabilities

"Calculate and release liabilities for a deleted offer."

```
function release_offer_liabilities(state, offer):
  (selling_liab, buying_liab) = offer_liabilities(offer.amount, offer.price)

  --- Release selling liability ---
  if offer.selling is Native:
    MUTATE account(offer.seller_id).liabilities.selling -= selling_liab
  else if seller is NOT the issuer of offer.selling:
    MUTATE trustline(offer.seller_id, offer.selling).liabilities.selling -= selling_liab

  --- Release buying liability ---
  if offer.buying is Native:
    MUTATE account(offer.seller_id).liabilities.buying -= buying_liab
  else if seller is NOT the issuer of offer.buying:
    MUTATE trustline(offer.seller_id, offer.buying).liabilities.buying -= buying_liab
```

**Calls:** [offer_liabilities](#helper-offer_liabilities), [ensure_account_liabilities](../execute.pc.md#helper-ensure_account_liabilities), [ensure_trustline_liabilities](../execute.pc.md#helper-ensure_trustline_liabilities), [issuer_for_asset](../execute.pc.md#helper-issuer_for_asset)

---

### Helper: offer_liabilities

```
function offer_liabilities(amount, price):
  result = exchange_v10_without_price_error_thresholds(
    price, amount, INT64_MAX, INT64_MAX, INT64_MAX, Normal)
  → (result.num_wheat_received, result.num_sheep_send)
```

**Calls:** `exchange_v10_without_price_error_thresholds` REF: operations/execute/offer_exchange::exchange_v10_without_price_error_thresholds

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~360   | ~120       |
| Functions     | 7      | 7          |
