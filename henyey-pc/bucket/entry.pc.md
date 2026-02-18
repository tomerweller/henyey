## Pseudocode: crates/bucket/src/entry.rs

"BucketEntry implementation for bucket storage."
"Entries in a bucket must be sorted by key for correct merge behavior."

### BucketEntry (enum)

"Entry Types and Merge Semantics (CAP-0020):"
"  Old + New → Result"
"  Init + Dead → Nothing (both annihilated)"
"  Dead + Init → Live (recreation)"
"  Init + Live → Init with new value"
"  Live + Dead → Dead (if keeping tombstones)"
"  Live + Live → Newer Live wins"

```
ENUM BucketEntry:
  Live(LedgerEntry)      // active ledger entry
  Dead(LedgerKey)        // tombstone marking deletion
  Init(LedgerEntry)      // CAP-0020: created in this merge window
  Metadata(BucketMetadata)  // protocol version, bucket list type
```

### from_xdr / from_xdr_entry

```
function from_xdr(bytes):
  xdr_entry = parse XDR BucketEntry from bytes
  → from_xdr_entry(xdr_entry)

function from_xdr_entry(xdr):
  Liveentry → Live(entry)
  Initentry → Init(entry)
  Deadentry → Dead(key)
  Metaentry → Metadata(meta)
```

### to_xdr_entry / to_xdr

```
function to_xdr_entry():
  Live(entry) → Liveentry(entry)
  Init(entry) → Initentry(entry)
  Dead(key)   → Deadentry(key)
  Metadata(m) → Metaentry(m)

function to_xdr():
  → serialize to_xdr_entry() to bytes
```

### key

```
function key():
  Live or Init: → extract key from ledger entry
  Dead:         → the key itself
  Metadata:     → nothing
```

**Calls**: [ledger_entry_to_key](#ledger_entry_to_key)

### Type predicates

```
function is_metadata(): → true if Metadata
function is_dead():     → true if Dead
function is_live():     → true if Live
function is_init():     → true if Init

function as_ledger_entry():
  Live or Init: → ledger entry reference
  otherwise:    → nothing

function entry_type():
  Live → Liveentry
  Dead → Deadentry
  Init → Initentry
  Metadata → Metaentry
```

### ledger_entry_to_key

"Extract a LedgerKey from a LedgerEntry."

```
function ledger_entry_to_key(entry):
  Account:          → Account(account_id)
  Trustline:        → Trustline(account_id, asset)
  Offer:            → Offer(seller_id, offer_id)
  Data:             → Data(account_id, data_name)
  ClaimableBalance: → ClaimableBalance(balance_id)
  LiquidityPool:    → LiquidityPool(liquidity_pool_id)
  ContractData:     → ContractData(contract, key, durability)
  ContractCode:     → ContractCode(hash)
  ConfigSetting:    → ConfigSetting(config_setting_id)
  Ttl:              → Ttl(key_hash)
```

### compare_keys

"Deterministic key ordering matching stellar-core."
"Critical for bucket merging — bucket hashes must match."

```
function compare_keys(a, b):
  a_type = ledger_key_type(a)
  b_type = ledger_key_type(b)
  if a_type != b_type:
    → compare a_type vs b_type
  → compare_keys_same_type(a, b)
```

**Calls**: [ledger_key_type](#ledger_key_type) | [compare_keys_same_type](#compare_keys_same_type)

### ledger_key_type

```
function ledger_key_type(key):
  Account → Account, Trustline → Trustline,
  Offer → Offer, Data → Data,
  ClaimableBalance → ClaimableBalance,
  LiquidityPool → LiquidityPool,
  ContractData → ContractData,
  ContractCode → ContractCode,
  ConfigSetting → ConfigSetting,
  Ttl → Ttl
```

### ledger_entry_data_type

```
function ledger_entry_data_type(data):
  "Maps each LedgerEntryData variant to its LedgerEntryType"
  Account → Account, Trustline → Trustline, ... etc
```

### Helper: compare_keys_same_type

"Within each type, compare by type-specific fields in XDR order."

```
function compare_keys_same_type(a, b):
  Account:          compare(account_id)
  Trustline:        compare(account_id) then compare(asset)
  Offer:            compare(seller_id) then compare(offer_id)
  Data:             compare(account_id) then compare(data_name)
  ClaimableBalance: compare(balance_id)
  LiquidityPool:    compare(liquidity_pool_id)
  ContractData:     compare_sc_address(contract)
                    then compare_sc_val(key)
                    then compare(durability)
  ContractCode:     compare(hash)
  ConfigSetting:    compare(config_setting_id)
  Ttl:              compare(key_hash)
```

**Calls**: [compare_sc_address](#compare_sc_address) | [compare_sc_val](#compare_sc_val)

### Helper: compare_sc_address

```
function compare_sc_address(a, b):
  "Use XDR byte comparison for correctness matching stellar-core xdrpp"
  a_bytes = serialize a to XDR
  b_bytes = serialize b to XDR
  → compare a_bytes vs b_bytes
```

### Helper: compare_sc_val

"Compare two ScVal values matching stellar-core order."
"Critical for bucket hash determinism across implementations."

```
function compare_sc_val(a, b):
  "Compare by type discriminant first"
  if type_of(a) != type_of(b):
    → compare discriminants

  "Same type — compare by value"
  Bool:     compare values
  Void:     equal
  Error:    compare XDR bytes
  U32/I32/U64/I64/Timepoint/Duration: compare values
  U128:     compare hi then lo
  I128:     compare hi then lo
  U256:     compare hi_hi, hi_lo, lo_hi, lo_lo
  I256:     compare XDR bytes
  Bytes:    compare byte slices
  String:   compare byte slices
  Symbol:   compare byte slices
  Vec:      element-wise compare_sc_val, then len
  Map:      entry-wise compare key then val, then len
  Address:  compare_sc_address
  LedgerKeyContractInstance: equal
  LedgerKeyNonce: compare nonce
  ContractInstance: compare XDR bytes
  fallback: compare XDR bytes
```

**Calls**: [compare_sc_address](#compare_sc_address) (recursive for Address)

### Helper: sc_val_type_discriminant

"Must match XDR ScValType enum discriminants exactly."

```
function sc_val_type_discriminant(v):
  Bool=0, Void=1, Error=2, U32=3, I32=4,
  U64=5, I64=6, Timepoint=7, Duration=8,
  U128=9, I128=10, U256=11, I256=12,
  Bytes=13, String=14, Symbol=15,
  Vec=16, Map=17, Address=18,
  ContractInstance=19,
  LedgerKeyContractInstance=20,
  LedgerKeyNonce=21
```

### compare_entries

"Metadata entries are always sorted first."

```
function compare_entries(a, b):
  key_a = a.key()
  key_b = b.key()
  if both have keys:  → compare_keys(key_a, key_b)
  if a is metadata:   → Less (metadata first)
  if b is metadata:   → Greater
  if both metadata:   → Equal
```

**Calls**: [compare_keys](#compare_keys)

### is_soroban_entry / is_soroban_key

"Soroban entries are the only types subject to eviction."

```
function is_soroban_entry(entry):
  → entry.data is ContractData or ContractCode

function is_soroban_key(key):
  → key is ContractData or ContractCode
```

### is_temporary_entry

"Temporary entries are deleted immediately on eviction,"
"NOT archived to hot archive bucket list."

```
function is_temporary_entry(entry):
  if entry.data is ContractData:
    → durability == Temporary
  → false
```

### is_persistent_entry

"Persistent entries are archived to hot archive on eviction."
"All ContractCode is persistent. ContractData with Persistent durability."

```
function is_persistent_entry(entry):
  if ContractCode: → true
  if ContractData: → durability == Persistent
  → false
```

### get_ttl_key

"TTL key is derived by SHA-256 hashing the original key's XDR."

```
function get_ttl_key(key):
  GUARD not a Soroban key → nothing
  key_bytes = serialize key to XDR
  hash = SHA-256(key_bytes)
  → Ttl(key_hash = hash)
```

### is_ttl_expired

```
function is_ttl_expired(ttl_entry, current_ledger):
  live_until = get_ttl_live_until(ttl_entry)
  GUARD live_until is nothing → nothing
  → live_until < current_ledger
```

**Calls**: [get_ttl_live_until](#get_ttl_live_until)

### get_ttl_live_until

```
function get_ttl_live_until(ttl_entry):
  if entry.data is Ttl:
    → ttl.live_until_ledger_seq
  → nothing
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 618    | 175        |
| Functions     | 21     | 21         |
