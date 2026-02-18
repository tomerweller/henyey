## Pseudocode: crates/tx/src/lumen_reconciler.rs

"LumenEventReconciler for XLM balance reconciliation."
"Handles a pre-protocol 8 edge case where XLM could be minted or burned
outside of normal operations. The reconciler calculates the total XLM
balance delta across all ledger entry changes and emits appropriate
mint/burn events if needed."

"Mint events are inserted at the beginning of the event list."

### Data Structures

```
struct LumenEventReconciler:
  balances     // map: AccountId → i64
  enabled      // boolean

struct ReconcilerConfig:
  enabled            // boolean
  protocol_version   // u32
```

### reconcile_events

```
function reconcile_events(tx_source_account, operation,
    delta, op_event_manager):

  GUARD not op_event_manager.is_enabled() → return

  balance_delta = calculate_balance_delta(delta)

  if balance_delta == 0:
    → return

  source_account = get_operation_source(
    tx_source_account, operation)
  source_address = ScAddress.Account(source_account)

  if balance_delta > 0:
    "XLM was created — emit mint event at beginning"
    op_event_manager.new_mint_event_at_beginning(
      Asset.Native, source_address, balance_delta)
  else:
    "XLM was destroyed — emit burn event"
    op_event_manager.new_burn_event(
      Asset.Native, source_address, -balance_delta)
```

**Calls:**
- [`OpEventManager.new_mint_event_at_beginning`](events.pc.md) — REF: events::OpEventManager
- [`OpEventManager.new_burn_event`](events.pc.md) — REF: events::OpEventManager

### Helper: calculate_balance_delta

```
function calculate_balance_delta(delta):
  total_delta = 0

  "Process updated entries (post-state vs pre-state)"
  for each (post, pre) in zip(delta.updated_entries(),
      delta.update_states()):
    post_balance = get_account_balance(post)
    pre_balance = get_account_balance(pre)
    total_delta += (post_balance - pre_balance)  (saturating)

  "Process created entries (add full balance)"
  for each entry in delta.created_entries():
    total_delta += get_account_balance(entry)  (saturating)

  "Process deleted entries (subtract full balance)"
  for each entry in delta.delete_states():
    total_delta -= get_account_balance(entry)  (saturating)

  → total_delta
```

### Helper: get_account_balance

```
function get_account_balance(entry):
  if entry is null:
    → 0
  if entry.data is Account:
    → entry.data.balance
  → 0
```

### Helper: get_operation_source

"Uses the operation's source account if specified, otherwise
falls back to the transaction source account."

```
function get_operation_source(tx_source, operation):
  if operation.source_account is not null:
    → muxed_to_account_id(operation.source_account)
  → muxed_to_account_id(tx_source)
```

**Calls:** [`muxed_to_account_id`](frame.pc.md) — REF: frame::muxed_to_account_id

### LumenEventReconciler.new / disabled

```
function new():
  → LumenEventReconciler { balances: {}, enabled: true }

function disabled():
  → LumenEventReconciler { balances: {}, enabled: false }
```

### LumenEventReconciler.track_balance

```
function track_balance(self, account_id, balance):
  if self.enabled:
    self.balances[account_id] = balance
```

### LumenEventReconciler.get_tracked_balance

```
function get_tracked_balance(self, account_id):
  → self.balances[account_id] or null
```

### LumenEventReconciler.calculate_account_delta

```
function calculate_account_delta(self, account_id,
    current_balance):
  GUARD not self.enabled → null
  prev = self.balances[account_id]
  if prev exists:
    → current_balance - prev
  → null
```

### LumenEventReconciler.calculate_total_delta

```
function calculate_total_delta(self, get_current_balance):
  GUARD not self.enabled → 0

  total = 0
  for each (account_id, prev_balance) in self.balances:
    current = get_current_balance(account_id)
    total += (current - prev_balance)
  → total
```

### LumenEventReconciler.clear

```
function clear(self):
  self.balances = {}
```

### ReconcilerConfig.for_protocol

```
function for_protocol(protocol_version):
  "Reconciliation is primarily needed for pre-protocol 8
   but kept enabled for all versions for consistency"
  → ReconcilerConfig {
      enabled: true,
      protocol_version: protocol_version
    }
```

### ReconcilerConfig.should_reconcile

```
function should_reconcile(self):
  → self.enabled
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 296    | 95         |
| Functions     | 13     | 13         |
