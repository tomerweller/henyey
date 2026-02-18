## Pseudocode: crates/tx/src/meta_builder.rs

"Transaction metadata building for live execution mode."
"Matches stellar-core implementation in TransactionMeta.cpp."

### DiagnosticConfig (struct)

```
DiagnosticConfig:
  enable_soroban_diagnostic_events        // bool
  enable_diagnostics_for_tx_submission    // bool
```

### DiagnosticEventManager (struct)

"Manages diagnostic events during transaction validation and application."
"Disabled managers are complete no-ops for performance."
"Finalization is one-time (asserts if called twice)."

```
DiagnosticEventManager:
  buffer[]     // list of DiagnosticEvent
  enabled      // bool
  finalized    // bool
```

### DiagnosticEventManager::create_for_apply

```
function create_for_apply(meta_enabled, is_soroban, config):
  enabled = meta_enabled AND is_soroban
    AND config.enable_soroban_diagnostic_events
  → DiagnosticEventManager { buffer: [], enabled, finalized: false }
```

### DiagnosticEventManager::create_for_validation

```
function create_for_validation(config):
  enabled = config.enable_diagnostics_for_tx_submission
  → DiagnosticEventManager { buffer: [], enabled, finalized: false }
```

### DiagnosticEventManager::push_error

```
function push_error(error, message, args):
  GUARD not enabled → return
  ASSERT: not finalized

  topics = [Symbol("error"), Error(error)]

  if args is empty:
    data = String(message)
  else:
    data = Map {
      "message" → String(message),
      "arg0" → args[0], "arg1" → args[1], ...
    }

  event = DiagnosticEvent {
    in_successful_contract_call: false,
    event: ContractEvent {
      type: DIAGNOSTIC,
      contract_id: null,
      body: V0 { topics, data }
    }
  }
  append event to buffer
```

### DiagnosticEventManager::push_event

```
function push_event(event):
  GUARD not enabled → return
  ASSERT: not finalized
  append event to buffer
```

### DiagnosticEventManager::push_metrics

```
function push_metrics(metrics):
  GUARD not enabled → return
  ASSERT: not finalized

  topics = [Symbol("core_metrics")]
  data = Map {
    "cpu_insn"          → metrics.cpu_insn,
    "mem_byte"          → metrics.mem_byte,
    "ledger_read_byte"  → metrics.ledger_read_byte,
    "ledger_write_byte" → metrics.ledger_write_byte,
    "emit_event"        → metrics.emit_event,
    "emit_event_byte"   → metrics.emit_event_byte,
    "invoke_time_nsecs" → metrics.invoke_time_nsecs
  }

  append DiagnosticEvent { type: DIAGNOSTIC, body: V0 { topics, data } }
    to buffer
```

### DiagnosticEventManager::finalize

"Can only be called once."

```
function finalize() → list:
  ASSERT: not finalized
  MUTATE finalized = true
  → take buffer (move contents out)
```

### ExecutionMetrics (struct)

```
ExecutionMetrics:
  cpu_insn, mem_byte, ledger_read_byte,
  ledger_write_byte, emit_event, emit_event_byte,
  invoke_time_nsecs
```

---

### OperationMetaBuilder (struct)

"Per-operation metadata including ledger changes and events."
"Matches stellar-core OperationMetaBuilder in TransactionMeta.cpp."

```
OperationMetaBuilder:
  enabled              // bool
  protocol_version     // int
  event_manager        // OpEventManager
  changes[]            // list of LedgerEntryChange
  soroban_return_value // optional ScVal
```

### OperationMetaBuilder::new

```
function new(enabled, protocol_version, is_soroban,
    network_id, memo, event_config):
  event_manager = OpEventManager.new(
    enabled, is_soroban, protocol_version,
    network_id, memo, event_config)
  → OperationMetaBuilder {
      enabled, protocol_version, event_manager,
      changes: [], soroban_return_value: null }
```

REF: events::OpEventManager::new

### OperationMetaBuilder::record_create

```
function record_create(entry):
  GUARD not enabled → return
  append Created(entry) to changes
```

### OperationMetaBuilder::record_update

"Emits STATE followed by UPDATED changes."

```
function record_update(pre_state, post_state):
  GUARD not enabled → return
  append State(pre_state) to changes
  append Updated(post_state) to changes
```

### OperationMetaBuilder::record_delete

"Emits STATE followed by REMOVED changes."

```
function record_delete(key, pre_state):
  GUARD not enabled → return
  append State(pre_state) to changes
  append Removed(key) to changes
```

### OperationMetaBuilder::record_restore

```
function record_restore(entry):
  GUARD not enabled → return
  append Restored(entry) to changes
```

### OperationMetaBuilder::set_ledger_changes

"Replaces any previously recorded changes."

```
function set_ledger_changes(changes):
  GUARD not enabled → return
  self.changes = changes
```

### OperationMetaBuilder::finalize_v2

```
function finalize_v2() → OperationMeta:
  → OperationMeta { changes: self.changes }
```

### OperationMetaBuilder::finalize_v4

```
function finalize_v4() → OperationMetaV2:
  events = self.event_manager.finalize()
  → OperationMetaV2 { changes: self.changes, events }
```

**Calls**: [OpEventManager::finalize](events.pc.md#opeventmanager-finalize)

---

### TransactionMetaBuilder (struct)

"Orchestrates metadata collection across all operations."
"Supports V2, V3, and V4 TransactionMeta formats."
"One-time finalization producing final XDR."

```
TransactionMetaBuilder:
  enabled                       // bool
  is_soroban                    // bool
  protocol_version              // int
  tx_changes_before[]           // ledger changes before ops
  tx_changes_after[]            // ledger changes after ops
  operation_builders[]          // per-op OperationMetaBuilder
  tx_event_manager              // TxEventManager
  diagnostic_event_manager      // DiagnosticEventManager
  non_refundable_resource_fee   // i64 (Soroban)
  refundable_fee_tracker        // optional RefundableFeeTracker
  finalized                     // bool
```

### TransactionMetaBuilder::new

```
function new(meta_enabled, frame, protocol_version,
    network_id, event_config, diagnostic_config):
  is_soroban = frame.is_soroban()
  memo = frame.memo()
  op_count = frame.operation_count()

  "Create operation builders for each operation"
  operation_builders = for i in 0..op_count:
    OperationMetaBuilder.new(meta_enabled, protocol_version,
      is_soroban, network_id, memo, event_config)

  tx_event_manager = TxEventManager.new(
    meta_enabled, protocol_version, network_id, event_config)

  diagnostic_event_manager =
    DiagnosticEventManager.create_for_apply(
      meta_enabled, is_soroban, diagnostic_config)

  → TransactionMetaBuilder { ... all fields ... }
```

**Calls**: [OperationMetaBuilder::new](#operationmetabuildernew) | [DiagnosticEventManager::create_for_apply](#diagnosticeventmanagercreate_for_apply)

### TransactionMetaBuilder::push_tx_changes_before

"Fee deduction and sequence number bump changes."

```
function push_tx_changes_before(changes):
  GUARD not enabled → return
  extend tx_changes_before with changes
```

### TransactionMetaBuilder::push_tx_changes_after

"Fee refunds for Soroban transactions."

```
function push_tx_changes_after(changes):
  GUARD not enabled → return
  extend tx_changes_after with changes
```

### TransactionMetaBuilder::meta_version

```
function meta_version() → int:
  "Protocol 20+ uses V4 for Soroban support"
  → 4
```

### TransactionMetaBuilder::finalize

```
function finalize(success) → TransactionMeta:
  ASSERT: not finalized
  MUTATE finalized = true

  if not enabled:
    → empty V2 TransactionMeta

  version = meta_version()
  if version == 2: → finalize_v2()
  if version == 3: → finalize_v3(success)
  if version == 4: → finalize_v4(success)
  else:            → finalize_v2()
```

**Calls**: [finalize_v2](#transactionmetabuilderfinalize_v2) | [finalize_v3](#transactionmetabuilderfinalize_v3) | [finalize_v4](#transactionmetabuilderfinalize_v4)

### TransactionMetaBuilder::finalize_v2

"Classic, no Soroban."

```
function finalize_v2() → TransactionMeta:
  operations = for each builder in operation_builders:
    builder.finalize_v2()

  → V2 {
    tx_changes_before,
    operations,
    tx_changes_after
  }
```

### TransactionMetaBuilder::finalize_v3

"Early Soroban, events at tx level."

```
function finalize_v3(success) → TransactionMeta:
  operations = for each builder in operation_builders:
    builder.finalize_v2()

  diagnostic_events = diagnostic_event_manager.finalize()

  "V3 has Soroban meta with events at transaction level"
  if is_soroban AND success:
    soroban_meta = SorobanTransactionMeta {
      events: [],
      return_value: Void,
      diagnostic_events
    }
  else:
    soroban_meta = null

  → V3 {
    tx_changes_before, operations,
    tx_changes_after, soroban_meta
  }
```

### TransactionMetaBuilder::finalize_v4

"Modern Soroban, per-op events."

```
function finalize_v4(success) → TransactionMeta:
  "V4 uses OperationMetaV2 with per-operation events"
  operations = for each builder in operation_builders:
    builder.finalize_v4()

  tx_events = tx_event_manager.finalize()
  diagnostic_events = diagnostic_event_manager.finalize()

  "Build Soroban meta V2 for resource fee tracking"
  if is_soroban AND success:
    if refundable_fee_tracker exists:
      ext = V1 {
        total_non_refundable_resource_fee_charged:
          non_refundable_resource_fee,
        total_refundable_resource_fee_charged:
          tracker.consumed_refundable_fee,
        rent_fee_charged: tracker.consumed_rent_fee
      }
    else:
      ext = V0

    soroban_meta = SorobanTransactionMetaV2 {
      ext,
      return_value: Void
    }
  else:
    soroban_meta = null

  → V4 {
    tx_changes_before, operations,
    tx_changes_after, soroban_meta,
    events: tx_events,
    diagnostic_events
  }
```

**Calls**: [OperationMetaBuilder::finalize_v4](#operationmetabuilderfinalize_v4) | [TxEventManager::finalize](events.pc.md#txeventmanager-finalize) | [DiagnosticEventManager::finalize](#diagnosticeventmanagerfinalize)

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 854    | ~220       |
| Functions     | 30     | 23         |

NOTE: 7 trivial accessor functions omitted (is_enabled, event_manager_mut,
operation_meta_builder_mut, operation_count, protocol_version,
soroban_return_value, set_soroban_return_value getters/setters).
