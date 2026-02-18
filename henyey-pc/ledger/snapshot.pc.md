## Pseudocode: crates/ledger/src/snapshot.rs

"Point-in-time snapshots of ledger state."
"Snapshots provide concurrent reads during ledger close: transaction processing
reads from a frozen snapshot while writes accumulate in the delta."

### LedgerSnapshot (struct)

```
STRUCT LedgerSnapshot:
  ledger_seq    // sequence number this snapshot represents
  header        // complete LedgerHeader
  header_hash   // SHA-256 of XDR-encoded header
  entries       // map<key_bytes → LedgerEntry>  (may be subset of full state)
```

### LedgerSnapshot::new

```
FUNCTION new(header, header_hash, entries):
  → LedgerSnapshot { ledger_seq: header.ledger_seq, header, header_hash, entries }
```

### LedgerSnapshot::empty

```
FUNCTION empty(ledger_seq):
  → LedgerSnapshot with zeroed header, empty entries, zero hash
```

### LedgerSnapshot::get_entry

```
FUNCTION get_entry(self, key):
  key_bytes = XDR_encode(key)                     REF: delta::key_to_bytes
  → entries.lookup(key_bytes) or None
```

### LedgerSnapshot::get_account

```
FUNCTION get_account(self, account_id):
  key = AccountKey { account_id }
  entry = self.get_entry(key)
  if entry exists AND entry.data is Account:
    → entry.data.account
  → None
```

### LedgerSnapshot::contains

```
FUNCTION contains(self, key):
  key_bytes = XDR_encode(key)
  → entries.has_key(key_bytes)
```

### LedgerSnapshot::set_id_pool

"Used during replay to set correct starting ID pool from previous ledger,
so that new offers get the correct IDs."

```
FUNCTION set_id_pool(self, id_pool):
  MUTATE self header.id_pool = id_pool
```

### LedgerSnapshot accessors

```
FUNCTION ledger_seq(self):   → self.ledger_seq
FUNCTION header(self):       → self.header
FUNCTION header_hash(self):  → self.header_hash
FUNCTION protocol_version(): → self.header.ledger_version
FUNCTION base_fee():         → self.header.base_fee
FUNCTION base_reserve():     → self.header.base_reserve
FUNCTION bucket_list_hash(): → self.header.bucket_list_hash
FUNCTION num_entries():      → self.entries.length
FUNCTION entries():          → iterator over self.entries.values
```

---

### Callback types

```
TYPE EntryLookupFn           = (LedgerKey) → LedgerEntry or None
TYPE EntriesLookupFn         = () → list of LedgerEntry
TYPE BatchEntryLookupFn      = (list of LedgerKey) → list of LedgerEntry
TYPE OffersByAccountAssetFn  = (AccountId, Asset) → list of LedgerEntry
```

---

### SnapshotHandle (struct)

"Thread-safe wrapper with optional lazy-loading lookup functions."

```
STRUCT SnapshotHandle:
  inner                         // shared LedgerSnapshot
  lookup_fn                     // optional: single-entry fallback lookup
  entries_fn                    // optional: full-state enumeration
  batch_lookup_fn               // optional: multi-key batch lookup
  offers_by_account_asset_fn    // optional: offer index lookup
  prefetch_cache                // shared mutable map<key_bytes → LedgerEntry>
```

### SnapshotHandle::new / with_lookup / with_lookups_and_entries

```
FUNCTION new(snapshot):
  → SnapshotHandle { inner: snapshot, all callbacks = None, empty cache }

FUNCTION with_lookup(snapshot, lookup_fn):
  → same as new but with lookup_fn set

FUNCTION with_lookups_and_entries(snapshot, lookup_fn, entries_fn):
  → same as new but with lookup_fn and entries_fn set
```

### <a id="snapshot_get_entry"></a>SnapshotHandle::get_entry

"Three-tier lookup: snapshot cache → prefetch cache → lookup function."

```
FUNCTION get_entry(self, key):
  "1. Check snapshot's built-in cache"
  entry = self.inner.get_entry(key)
  if entry found:
    → entry

  "2. Check prefetch cache (skip for Soroban keys — they're never cached)"
  if NOT is_soroban_key(key):
    key_bytes = XDR_encode(key)
    entry = self.prefetch_cache.read().lookup(key_bytes)
    if entry found:
      → entry

  "3. Fall back to lookup function if available"
  if self.lookup_fn exists:
    → self.lookup_fn(key)

  → None
```

**Calls**: [is_soroban_key](#is_soroban_key)

### SnapshotHandle::get_account

```
FUNCTION get_account(self, account_id):
  key = AccountKey { account_id }
  entry = self.get_entry(key)
  if entry exists AND entry.data is Account:
    → entry.data.account
  → None
```

**Calls**: [get_entry](#snapshot_get_entry)

### SnapshotHandle::load_entries

"Batch load: snapshot cache → prefetch cache → batch/individual fallback."

```
FUNCTION load_entries(self, keys):
  result = []
  remaining = []
  prefetch = self.prefetch_cache.read()

  for each key in keys:
    if inner.get_entry(key) found:
      append to result
    else if NOT is_soroban_key(key):
      key_bytes = XDR_encode(key)
      if prefetch.has(key_bytes):
        append prefetch[key_bytes] to result
      else:
        append key to remaining
    else:
      append key to remaining

  release prefetch read lock

  if remaining is empty:
    → result

  if batch_lookup_fn exists:
    result += batch_lookup_fn(remaining)
  else if lookup_fn exists:
    for each key in remaining:
      entry = lookup_fn(key)
      if entry found:
        append to result

  → result
```

**Calls**: [is_soroban_key](#is_soroban_key)

### SnapshotHandle::offers_by_account_and_asset

```
FUNCTION offers_by_account_and_asset(self, account_id, asset):
  if self.offers_by_account_asset_fn exists:
    → self.offers_by_account_asset_fn(account_id, asset)

  "Fallback: linear scan over all entries"
  entries = self.all_entries()
  → filter entries where:
      entry.data is Offer
      AND offer.seller_id == account_id
      AND (offer.buying == asset OR offer.selling == asset)
```

### SnapshotHandle::all_entries

```
FUNCTION all_entries(self):
  if self.entries_fn exists:
    → self.entries_fn()
  → self.inner.entries.values
```

### <a id="prefetch"></a>SnapshotHandle::prefetch

"Bulk-load keys into prefetch cache. Soroban types are skipped
(they're in-memory via InMemorySorobanState)."

```
FUNCTION prefetch(self, keys):
  needed = []
  cache = self.prefetch_cache.read()

  for each key in keys:
    if is_soroban_key(key):
      continue
    key_bytes = XDR_encode(key)
    if inner.get_entry(key) found OR cache.has(key_bytes):
      continue
    append key to needed

  release read lock

  if needed is empty:
    → PrefetchStats { requested: 0, loaded: 0 }

  "Batch load from bucket list"
  if batch_lookup_fn exists:
    entries = batch_lookup_fn(needed)
  else if lookup_fn exists:
    entries = []
    for each k in needed:
      entry = lookup_fn(k)
      if found: append to entries
  else:
    → PrefetchStats { requested: needed.length, loaded: 0 }

  loaded = entries.length
  cache = self.prefetch_cache.write()
  for each entry in entries:
    key = entry_to_key(entry)             REF: delta::entry_to_key
    key_bytes = XDR_encode(key)
    cache.insert(key_bytes, entry)

  → PrefetchStats { requested: needed.length, loaded }
```

**Calls**: [is_soroban_key](#is_soroban_key)

---

### <a id="is_soroban_key"></a>Helper: is_soroban_key

```
FUNCTION is_soroban_key(key):
  → key is ContractData OR ContractCode OR Ttl
```

---

### SnapshotBuilder (struct)

"Fluent builder for constructing LedgerSnapshot instances."

```
STRUCT SnapshotBuilder:
  ledger_seq
  header        // optional
  header_hash
  entries       // map<key_bytes → LedgerEntry>
```

### SnapshotBuilder::new

```
FUNCTION new(ledger_seq):
  → SnapshotBuilder { ledger_seq, header: None, hash: ZERO, entries: {} }
```

### SnapshotBuilder::with_header

```
FUNCTION with_header(self, header, hash):
  MUTATE self header = header
  MUTATE self header_hash = hash
  → self
```

### SnapshotBuilder::add_entry

```
FUNCTION add_entry(self, key, entry):
  key_bytes = XDR_encode(key)
  self.entries.insert(key_bytes, entry)
  → self
```

### SnapshotBuilder::add_entries

```
FUNCTION add_entries(self, entries):
  for each (key, entry) in entries:
    key_bytes = XDR_encode(key)
    self.entries.insert(key_bytes, entry)
  → self
```

### SnapshotBuilder::build

```
FUNCTION build(self):
  GUARD self.header is None → Snapshot("header not set")
  → LedgerSnapshot { ledger_seq, header, header_hash, entries }
```

### SnapshotBuilder::build_with_default_header

```
FUNCTION build_with_default_header(self):
  header = self.header OR default header with:
    ledger_version = 20, ledger_seq = self.ledger_seq,
    total_coins = 100_000_000_000_000_000,
    base_fee = 100, base_reserve = 5_000_000,
    max_tx_set_size = 1000
  → LedgerSnapshot { ledger_seq, header, header_hash, entries }
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 638    | 175        |
| Functions     | 25     | 22         |
