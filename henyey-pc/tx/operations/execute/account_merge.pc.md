## Pseudocode: crates/tx/src/operations/execute/account_merge.rs

### execute_account_merge

```
function execute_account_merge(dest_muxed, source, state, context):
  dest_account_id = muxed_to_account_id(dest_muxed)
    REF: frame::muxed_to_account_id

  GUARD destination does not exist         → NO_ACCOUNT
  GUARD dest_account_id == source          → MALFORMED

  source_account = state.get_account(source)

  "Check source is not immutable (checked first per stellar-core
   doApplyFromV16)"
  CONST AUTH_IMMUTABLE_FLAG = 0x4
  GUARD source_account.flags & AUTH_IMMUTABLE_FLAG != 0
                                           → IMMUTABLE_SET

  "Check source has no sub-entries besides signers"
  GUARD source_account.num_sub_entries
        != source_account.signers.length   → HAS_SUB_ENTRIES

  --- Phase: Sequence number checks ---
  starting_seq = state.starting_sequence_number()

  if max_seq_num_to_apply exists for source_key:
    GUARD max_seq >= starting_seq           → SEQNUM_TOO_FAR

  GUARD source_account.seq_num >= starting_seq
                                           → SEQNUM_TOO_FAR

  GUARD num_sponsoring(source_account) > 0 → IS_SPONSOR

  --- Phase: Transfer balance ---
  source_balance = source_account.balance

  dest_acc = state.get_account_mut(dest_account_id)
  GUARD add_account_balance(dest_acc, source_balance) fails
                                           → DEST_FULL
    REF: mod::add_account_balance

  --- Phase: Clean up sponsorships ---
  if source has sponsored signers:
    for each sponsor in signer_sponsoring_ids(source_account):
      state.update_num_sponsoring(sponsor, -1)

  if source account entry is sponsored:
    state.remove_entry_sponsorship_and_update_counts(
      account_key, source, multiplier=2)

  --- Phase: Flush and delete ---
  "Flush ALL account changes EXCEPT the source being deleted,
   before recording deletion. stellar-core records all pending
   account STATE/UPDATED pairs before the source deletion."
  state.flush_all_accounts_except(source)

  state.delete_account(source)

  → SUCCESS(source_balance)
```

### Helper: num_sponsoring

```
function num_sponsoring(account):
  if account has v2 extension:
    → account.ext.v2.num_sponsoring
  → 0
```

### Helper: signer_sponsoring_ids

```
function signer_sponsoring_ids(account):
  if account has v2 extension:
    sponsors = []
    for each descriptor in v2.signer_sponsoring_ids:
      if descriptor has sponsor_id:
        append sponsor_id to sponsors
    → sponsors
  → none
```

**Calls**: [muxed_to_account_id](../../frame.pc.md#muxed_to_account_id) | [add_account_balance](mod.pc.md#add_account_balance) | [flush_all_accounts_except](../../state.pc.md#flush_all_accounts_except)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 144    | 55         |
| Functions     | 3      | 3          |
