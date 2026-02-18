## Pseudocode: crates/tx/src/operations/execute/create_account.rs

### execute_create_account

```
function execute_create_account(op, source, state, context):
  CONST ACCOUNT_MULTIPLIER = 2  // account counts as 2 base entries

  sponsor = state.active_sponsor_for(op.destination)

  "Check destination doesn't already exist (matches upstream doApply)"
  GUARD destination already exists   → ALREADY_EXIST

  --- Phase: Sponsorship / reserve check ---
  "Matches upstream createEntryWithPossibleSponsorship which runs
   before the source available-balance check"

  if sponsor exists:
    "Sponsored path: verify sponsor can afford the new account's reserve"
    sponsor_account = state.get_account(sponsor)
    (num_sponsoring, num_sponsored) =
      state.sponsorship_counts_for_account(sponsor)
    sponsor_min_balance = minimum_balance_with_counts(
      protocol_version,
      sponsor_account.num_sub_entries,
      num_sponsoring + ACCOUNT_MULTIPLIER,
      num_sponsored)
    available = sponsor_account.balance
              - account_liabilities(sponsor_account).selling
      REF: mod::account_liabilities
    GUARD available < sponsor_min_balance   → LOW_RESERVE
  else:
    "Non-sponsored path: starting balance must meet minimum reserve"
    min_balance = minimum_balance_with_counts(
      protocol_version, 0, 0, 0)
    GUARD op.starting_balance < min_balance  → LOW_RESERVE

  --- Phase: Source balance check ---
  source_account = state.get_account(source)

  "If source is the sponsor, its numSponsoring has already been
   incremented by createEntryWithPossibleSponsorship in stellar-core
   before this check, so we must include the sponsoring delta in
   the minimum balance."
  sponsoring_delta = ACCOUNT_MULTIPLIER if sponsor == source
                     else 0

  source_min_balance = minimum_balance_for_account_with_deltas(
    source_account, protocol_version,
    sub_entry_delta=0,
    sponsoring_delta,
    sponsored_delta=0)

  available = (source_account.balance - source_min_balance)
            - account_liabilities(source_account).selling
    REF: mod::account_liabilities

  GUARD available < op.starting_balance     → UNDERFUNDED

  --- Phase: Create the account ---
  if op.starting_balance != 0:
    MUTATE source_account balance -= op.starting_balance

  starting_seq = state.starting_sequence_number()

  new_account = AccountEntry {
    account_id:     op.destination,
    balance:        op.starting_balance,
    seq_num:        starting_seq,
    num_sub_entries: 0,
    flags:          0,
    thresholds:     [1, 0, 0, 0],
  }

  if sponsor exists:
    state.set_entry_sponsor(account_key, sponsor)
    state.apply_account_entry_sponsorship(
      new_account, sponsor, ACCOUNT_MULTIPLIER)

  state.create_account(new_account)

  → SUCCESS
```

**Calls**: [account_liabilities](mod.pc.md#account_liabilities) | [active_sponsor_for](../../state.pc.md#active_sponsor_for) | [apply_account_entry_sponsorship](../../state.pc.md#apply_account_entry_sponsorship)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 126    | 55         |
| Functions     | 1      | 1          |
