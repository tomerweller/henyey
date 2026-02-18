## Pseudocode: crates/tx/src/operations/execute/clawback.rs

### execute_clawback

"Claws back an amount of an asset from an account's trustline.
 The source account must be the issuer of the asset and the
 trustline must have the TRUSTLINE_CLAWBACK_ENABLED flag set."

```
function execute_clawback(op, source, state, context):
  CONST TRUSTLINE_CLAWBACK_ENABLED_FLAG = TrustLineFlags.ClawbackEnabled

  from_account_id = muxed_to_account_id(op.from)
    REF: frame::muxed_to_account_id

  "Cannot clawback from self (stellar-core doCheckValid checks
   this first)"
  GUARD from_account_id == source          → MALFORMED
  GUARD op.amount <= 0                     → MALFORMED
  GUARD op.asset is native                 → MALFORMED
  GUARD asset is not valid                 → MALFORMED

  "Verify source is the issuer of the asset"
  asset_issuer = issuer_of(op.asset)
  GUARD asset_issuer != source             → MALFORMED

  --- Phase: Trustline validation ---
  trustline = state.get_trustline(from_account_id, op.asset)
  GUARD trustline not found                → NO_TRUST

  "Check trustline has TRUSTLINE_CLAWBACK_ENABLED flag set.
   Per stellar-core, we check the trustline flag, not the issuer
   account flag."
  GUARD trustline.flags & TRUSTLINE_CLAWBACK_ENABLED_FLAG == 0
                                           → NOT_CLAWBACK_ENABLED

  GUARD trustline.balance < op.amount      → UNDERFUNDED

  --- Phase: Execute clawback ---
  MUTATE trustline balance -= op.amount

  → SUCCESS
```

**Calls**: [muxed_to_account_id](../../frame.pc.md#muxed_to_account_id) | [is_asset_valid](mod.pc.md#is_asset_valid)

---

### execute_clawback_claimable_balance

"Claws back an entire claimable balance. The source account must
 be the issuer of the asset in the claimable balance."

```
function execute_clawback_claimable_balance(op, source, state, context):
  entry = state.get_claimable_balance(op.balance_id)
  GUARD entry not found                    → DOES_NOT_EXIST

  "Cannot clawback native asset — stellar-core returns NOT_ISSUER"
  GUARD entry.asset is native              → NOT_ISSUER

  "Verify source is the issuer of the asset"
  asset_issuer = issuer_of(entry.asset)
  GUARD asset_issuer != source             → NOT_ISSUER

  "Check the claimable balance entry itself has CLAWBACK_ENABLED flag
   (stellar-core checks isClawbackEnabledOnClaimableBalance, NOT the
   issuer account)"
  cb_clawback_enabled = entry.ext.v1.flags
                      & CB_CLAWBACK_ENABLED_FLAG != 0
  GUARD not cb_clawback_enabled            → NOT_CLAWBACK_ENABLED

  "Load source account after all validation (matches stellar-core
   ordering)"
  GUARD source account not found           → NOT_ISSUER

  --- Phase: Delete claimable balance ---
  sponsorship_multiplier = entry.claimants.length
  sponsor = state.entry_sponsor(balance_key)

  state.delete_claimable_balance(op.balance_id)

  if sponsor exists:
    state.update_num_sponsoring(sponsor,
                                -sponsorship_multiplier)

  → SUCCESS
```

**Calls**: [entry_sponsor](../../state.pc.md#entry_sponsor) | [update_num_sponsoring](../../state.pc.md#update_num_sponsoring)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 175    | 50         |
| Functions     | 2      | 2          |
