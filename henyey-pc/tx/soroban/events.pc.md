## Pseudocode: crates/tx/src/soroban/events.rs

"Soroban contract event handling."
"Records events emitted during contract execution."

### Data Structures

```
enum EventType:
  Contract     // regular contract event
  System       // created/deleted entries
  Diagnostic   // debug info

struct ContractEvent:
  event_type       // EventType
  contract_id      // contract hash, or null
  topics           // list of ScVal (indexed fields)
  data             // ScVal

struct ContractEvents:
  events               // list of non-diagnostic events
  diagnostic_events    // list of diagnostic events
```

### ContractEvent.new

```
function new(event_type, contract_id, topics, data):
  → ContractEvent { event_type, contract_id, topics, data }
```

### ContractEvent.entry_created

```
function entry_created(contract_id, key):
  → ContractEvent {
      event_type: System,
      contract_id: contract_id,
      topics: [Symbol("entry_created")],
      data: key
    }
```

### ContractEvent.entry_deleted

```
function entry_deleted(contract_id, key):
  → ContractEvent {
      event_type: System,
      contract_id: contract_id,
      topics: [Symbol("entry_deleted")],
      data: key
    }
```

### ContractEvent.hash

```
function hash(self):
  hasher = SHA256()
  hasher.update(self.event_type as byte)

  if self.contract_id is not null:
    hasher.update(self.contract_id bytes)

  for each topic in self.topics:
    hasher.update(xdr_encode(topic))

  hasher.update(xdr_encode(self.data))
  → hasher.finalize()
```

### ContractEvents.push

```
function push(self, event):
  if event.event_type == Diagnostic:
    append event to self.diagnostic_events
  else:
    append event to self.events
```

### ContractEvents.hash

```
function hash(self):
  if self.events is empty:
    → zeroed 32-byte hash

  hasher = SHA256()
  for each event in self.events:
    hasher.update(event.hash())
  → hasher.finalize()
```

### ContractEvents.to_xdr

```
function to_xdr(self):
  → self.events
      .map(event_to_xdr)
      .filter(non-null)
```

### Helper: event_to_xdr

```
function event_to_xdr(event):
  event_type = map event.event_type to XDR enum
  body = ContractEventV0 {
    topics: event.topics,
    data: event.data
  }
  → XdrContractEvent {
      contract_id: event.contract_id,
      type: event_type,
      body: body
    }
```

### ContractEvents.clear

```
function clear(self):
  self.events = []
  self.diagnostic_events = []
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 198    | 74         |
| Functions     | 11     | 9          |
