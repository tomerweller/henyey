## Pseudocode: crates/tx/src/soroban/protocol/types.rs

"Shared types for protocol-versioned host implementations."

### Data Structures

```
struct InvokeHostFunctionOutput:
  return_value         // ScVal return from contract
  ledger_changes       // list of LedgerEntryChange
  contract_events      // decoded events (Contract + System)
                       // "for InvokeHostFunctionSuccessPreImage"
  encoded_contract_events  // all encoded events (diagnostic)
  cpu_insns            // CPU instructions consumed
  mem_bytes            // memory bytes consumed
  live_bucket_list_restores  // entries restored from
                       // live BL (expired TTL, not evicted)

struct LiveBucketListRestore:
  key                  // LedgerKey of restored entry
  entry                // pre-modification LedgerEntry
  ttl_key              // TTL LedgerKey for this entry
  ttl_entry            // TTL LedgerEntry (old expired TTL)

struct LedgerEntryChange:
  key                  // LedgerKey that was changed
  new_entry            // new entry value, or null if deleted
  ttl_change           // TtlChange if applicable
  old_entry_size_bytes // for rent calculation

struct TtlChange:
  old_live_until_ledger
  new_live_until_ledger

struct EncodedContractEvent:
  encoded_event        // XDR-encoded event bytes
  in_successful_call   // true if from successful call
```

### TtlChange.is_extended

"stellar-core only emits TTL changes when TTL is extended."

```
function is_extended(self):
  → self.new_live_until_ledger > self.old_live_until_ledger
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 77     | 32         |
| Functions     | 1      | 1          |
