## Pseudocode: crates/tx/src/operations/execute/bump_sequence.rs

### execute_bump_sequence

```
function execute_bump_sequence(op, source, state, context):
  GUARD op.bump_to < 0              → BAD_SEQ

  source_account = state.get_account(source)

  current = source_account.seq_num

  "Only bump if new sequence is higher"
  if op.bump_to > current:
    MUTATE source_account seq_num = op.bump_to

  "Always refresh seq metadata (protocol 19+ behavior)"
  update_account_seq_info(source_account, context.sequence,
                          context.close_time)
    REF: state::update_account_seq_info

  state.update_account(source_account)

  → SUCCESS
```

**Calls**: [update_account_seq_info](../../state.pc.md#update_account_seq_info)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 45     | 17         |
| Functions     | 1      | 1          |
