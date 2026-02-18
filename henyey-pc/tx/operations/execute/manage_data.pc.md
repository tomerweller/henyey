## Pseudocode: crates/tx/src/operations/execute/manage_data.rs

"ManageData operation execution."
"Allows accounts to attach arbitrary key-value data."

CONST MAX_DATA_NAME_LENGTH  = 64
CONST MAX_DATA_VALUE_LENGTH = 64
CONST ACCOUNT_SUBENTRY_LIMIT = 1000

### execute_manage_data

```
function execute_manage_data(op, source, state, context):

  "--- Validate data name ---"

  data_name = op.data_name as string
  GUARD data_name is empty
    OR data_name.length > MAX_DATA_NAME_LENGTH
    → InvalidName

  GUARD data_name bytes contain non-ASCII
    or ASCII control characters
    → InvalidName

  "--- Validate data value ---"

  if op.data_value is present:
    GUARD op.data_value.length > MAX_DATA_VALUE_LENGTH
      → InvalidName

  "--- Check source account ---"

  GUARD source account not found → error(SourceAccountNotFound)

  existing_entry = state.get_data(source, data_name)
  sponsor = state.active_sponsor_for(source)

  "--- Delete path ---"

  if op.data_value is absent:
    if existing_entry exists:
      if entry has sponsor:
        remove sponsorship and update counts

      MUTATE source.num_sub_entries -= 1
      state.delete_data(source, data_name)

    else:
      → NameNotFound

  "--- Create / Update path ---"

  else:
    if existing_entry exists:
      MUTATE entry.data_value = op.data_value

    else:
      "--- New entry: subentry limit check ---"

      GUARD source.num_sub_entries >= ACCOUNT_SUBENTRY_LIMIT
        → OpTooManySubentries

      "--- New entry: reserve check ---"

      if sponsor is present:
        new_min_balance = minimum_balance(sponsor, +1 subentry)
        available = sponsor.balance - sponsor.selling_liabilities
        GUARD available < new_min_balance → LowReserve
      else:
        new_min_balance = minimum_balance(source, +1 subentry)
        available = source.balance - source.selling_liabilities
        GUARD available < new_min_balance → LowReserve

      "--- Create the entry ---"

      new_entry = DataEntry {
        account_id: source,
        data_name: op.data_name,
        data_value: op.data_value
      }

      if sponsor is present:
        apply_entry_sponsorship(ledger_key, sponsor, source)

      state.create_data(new_entry)
      MUTATE source.num_sub_entries += 1

  → Success
```

**Calls**: [account_liabilities](../mod.pc.md#account_liabilities) | [minimum_balance_for_account](../../state.pc.md#minimum_balance_for_account)

### Helper: is_string_valid

```
function is_string_valid(bytes):
  → all bytes are ASCII and not ASCII control characters
```

## Summary
| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 196    | 63         |
| Functions    | 3      | 2          |
