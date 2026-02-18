## Pseudocode: crates/tx/src/soroban/storage.rs

"Soroban storage adapter."
"Provides a storage interface for contract state that integrates
with LedgerStateManager."

### Data Structures

```
struct StorageKey:
  contract     // ScAddress
  key          // ScVal
  durability   // Persistent | Temporary

struct StorageEntry:
  key          // StorageKey
  value        // ScVal
  live_until   // ledger seq when entry expires

struct SorobanStorage:
  read_entries   // map: StorageKey → StorageEntry or null
  write_entries  // map: StorageKey → StorageEntry or null
  code_entries   // map: Hash → bytes or null
```

### StorageKey.to_ledger_key

```
function to_ledger_key(self):
  → LedgerKey.ContractData {
      contract: self.contract,
      key: self.key,
      durability: self.durability
    }
```

### StorageKey.hash

```
function hash(self):
  ledger_key = self.to_ledger_key()
  → SHA256(xdr_encode(ledger_key))
```

### StorageEntry.is_expired

```
function is_expired(self, current_ledger):
  → self.live_until < current_ledger
```

### StorageEntry.to_contract_data_entry

```
function to_contract_data_entry(self):
  → ContractDataEntry {
      contract: self.key.contract,
      key: self.key.key,
      durability: self.key.durability,
      val: self.value
    }
```

### SorobanStorage.record_read

```
function record_read(self, key, entry):
  "Only insert if key not already present"
  if key not in self.read_entries:
    self.read_entries[key] = entry
```

### SorobanStorage.record_write

```
function record_write(self, key, entry):
  self.write_entries[key] = entry
```

### SorobanStorage.get

```
function get(self, key):
  "Check writes first (most recent value)"
  if key in self.write_entries:
    → self.write_entries[key]
  if key in self.read_entries:
    → self.read_entries[key]
  → null
```

### SorobanStorage.has

```
function has(self, key):
  → self.get(key) is not null
```

### SorobanStorage.put

```
function put(self, key, value, live_until):
  entry = new StorageEntry(key, value, live_until)
  self.record_write(key, entry)
```

### SorobanStorage.del

```
function del(self, key):
  self.record_write(key, null)
```

### SorobanStorage.record_code_read

```
function record_code_read(self, hash, code):
  if hash not in self.code_entries:
    self.code_entries[hash] = code
```

### SorobanStorage.get_code

```
function get_code(self, hash):
  → self.code_entries[hash] or null
```

### SorobanStorage.created_entries

```
function created_entries(self):
  "New writes that weren't in reads"
  → [entry for (key, entry) in self.write_entries
      where entry is not null
        AND key not in self.read_entries]
```

### SorobanStorage.updated_entries

```
function updated_entries(self):
  "Writes that were already in reads"
  → [entry for (key, entry) in self.write_entries
      where entry is not null
        AND key in self.read_entries]
```

### SorobanStorage.deleted_entries

```
function deleted_entries(self):
  "Writes of null for keys that were in reads"
  → [key for (key, entry) in self.write_entries
      where entry is null
        AND key in self.read_entries]
```

### SorobanStorage.clear

```
function clear(self):
  self.read_entries = {}
  self.write_entries = {}
  self.code_entries = {}
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 215    | 93         |
| Functions     | 17     | 17         |
