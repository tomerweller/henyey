## Pseudocode: crates/tx/src/frame.rs

### TransactionFrame (struct)

"Wrapper around TransactionEnvelope providing unified access to
transaction data across V0, V1, and FeeBump envelope types."

```
fields:
  envelope    : TransactionEnvelope
  hash        : cached Hash256 (lazily computed)
  network_id  : NetworkId (set when hash is cached)
```

---

### TransactionFrame::new

```
→ TransactionFrame { envelope, hash: nil, network_id: nil }
```

---

### TransactionFrame::with_network

```
→ TransactionFrame { envelope, hash: nil, network_id }
```

---

### TransactionFrame::hash

```
payload = signature_payload(network_id)
bytes = serialize_to_xdr(payload)
→ sha256(bytes)
```

**Calls:** [`sha256`](../../henyey-crypto)

---

### TransactionFrame::compute_hash

```
hash = self.hash(network_id)
MUTATE self.hash = hash
MUTATE self.network_id = network_id
→ hash
```

---

### Helper: signature_payload

```
envelope type switch:
  TxV0:
    tx = v0_to_v1_transaction(env.tx)
    tagged = TaggedTransaction::Tx(tx)
  Tx:
    tagged = TaggedTransaction::Tx(env.tx)
  TxFeeBump:
    tagged = TaggedTransaction::TxFeeBump(env.tx)

→ TransactionSignaturePayload { network_id, tagged }
```

---

### Helper: v0_to_v1_transaction

"V0 stores raw Ed25519 bytes; V1 uses MuxedAccount."

```
source_account = MuxedAccount::Ed25519(v0.source_account_ed25519)
→ Transaction {
    source_account,
    fee: v0.fee,
    seq_num: v0.seq_num,
    cond: Preconditions::None,
    memo: v0.memo,
    operations: v0.operations,
    ext: V0
  }
```

---

### TransactionFrame::source_account

```
envelope type switch:
  TxV0     → MuxedAccount::Ed25519(env.tx.source_account_ed25519)
  Tx       → env.tx.source_account
  FeeBump  → env.tx.fee_source
```

---

### TransactionFrame::source_account_id

```
→ muxed_to_account_id(self.source_account())
```

**Calls:** [`muxed_to_account_id`](#muxed_to_account_id)

---

### TransactionFrame::fee_source_account

```
envelope type switch:
  TxV0     → MuxedAccount::Ed25519(env.tx.source_account_ed25519)
  Tx       → env.tx.source_account
  FeeBump  → env.tx.fee_source
```

---

### TransactionFrame::inner_source_account

```
envelope type switch:
  TxV0     → MuxedAccount::Ed25519(env.tx.source_account_ed25519)
  Tx       → env.tx.source_account
  FeeBump  → env.tx.inner_tx.tx.source_account
```

---

### TransactionFrame::sequence_number

```
envelope type switch:
  TxV0     → env.tx.seq_num
  Tx       → env.tx.seq_num
  FeeBump  → env.tx.inner_tx.tx.seq_num
```

---

### TransactionFrame::fee

```
envelope type switch:
  TxV0     → env.tx.fee
  Tx       → env.tx.fee
  FeeBump  → min(env.tx.fee, U32_MAX) as u32
```

---

### TransactionFrame::total_fee

```
envelope type switch:
  TxV0     → env.tx.fee as i64
  Tx       → env.tx.fee as i64
  FeeBump  → env.tx.fee  (already i64)
```

---

### TransactionFrame::declared_soroban_resource_fee

```
if not soroban:
  → 0
→ soroban_data().resource_fee or 0
```

---

### TransactionFrame::inclusion_fee

```
if soroban:
  resource_fee = declared_soroban_resource_fee()
  ASSERT: resource_fee >= 0
  → total_fee() - resource_fee
→ total_fee()
```

---

### TransactionFrame::refundable_fee

"Parity: TransactionFrame::getRefundableFee() in stellar-core."

```
if not soroban:
  → nil
resource_fee = declared_soroban_resource_fee()
if resource_fee > 0:
  → resource_fee
→ nil
```

---

### TransactionFrame::inner_fee

```
envelope type switch:
  TxV0     → env.tx.fee
  Tx       → env.tx.fee
  FeeBump  → env.tx.inner_tx.tx.fee
```

---

### TransactionFrame::operations

```
envelope type switch:
  TxV0     → env.tx.operations
  Tx       → env.tx.operations
  FeeBump  → env.tx.inner_tx.tx.operations
```

---

### TransactionFrame::keys_for_fee_processing

```
keys = [ AccountKey(source_account_id()) ]
if is_fee_bump:
  inner = inner_source_account_id()
  if inner != source_account_id():
    append AccountKey(inner) to keys
→ keys
```

---

### TransactionFrame::keys_for_apply

"Collect statically-known keys needed for transaction apply."

```
keys = set()
source = inner_source_account_id()
for each op in operations:
  op_source = op.source_account or source
  if op_source != source:
    insert AccountKey(op_source) into keys
  collect_prefetch_keys(op.body, op_source, keys)
→ keys
```

**Calls:** [`collect_prefetch_keys`](operations/execute/prefetch.rs)

---

### TransactionFrame::preconditions

```
envelope type switch:
  TxV0:
    if time_bounds present → Preconditions::Time(time_bounds)
    else                   → Preconditions::None
  Tx       → env.tx.cond
  FeeBump  → env.tx.inner_tx.tx.cond
```

---

### TransactionFrame::signatures / inner_signatures

```
envelope type switch:
  TxV0     → env.signatures
  Tx       → env.signatures
  FeeBump:
    signatures()       → env.signatures       (outer)
    inner_signatures() → env.tx.inner_tx.signatures
```

---

### TransactionFrame::is_fee_bump

```
→ envelope is TxFeeBump
```

---

### TransactionFrame::is_soroban

```
→ any operation is InvokeHostFunction
    or ExtendFootprintTtl
    or RestoreFootprint
```

---

### TransactionFrame::has_dex_operations

```
→ any operation is ManageSellOffer
    or ManageBuyOffer
    or CreatePassiveSellOffer
    or PathPaymentStrictSend
    or PathPaymentStrictReceive
```

---

### TransactionFrame::soroban_data

```
envelope type switch:
  TxV0 → nil
  Tx:
    if env.tx.ext is V1 → ext data
    else                 → nil
  FeeBump:
    if inner_tx.tx.ext is V1 → ext data
    else                      → nil
```

---

### TransactionFrame::resources

```
tx_size = tx_size_bytes()

if soroban:
  resources = soroban_data().resources or fallback(empty)
  op_count = 1
  disk_read_entries = soroban_disk_read_entries(...)
  write_entries = read_write footprint length

  → Resource([op_count, instructions, tx_size,
              disk_read_bytes, write_bytes,
              disk_read_entries, write_entries])

if use_byte_limit_in_classic:
  → Resource([operation_count, tx_size])
else:
  → Resource([operation_count])
```

**Calls:** [`soroban_disk_read_entries`](#soroban_disk_read_entries)

---

### TransactionFrame::inner_tx_size_bytes

"For fee bump, returns inner envelope size (matches stellar-core
FeeBumpTransactionFrame::getResources delegation)."

```
if FeeBump:
  inner_envelope = Tx(inner_tx)
  → serialize_to_xdr(inner_envelope).len
else:
  → tx_size_bytes()
```

---

### TransactionFrame::soroban_transaction_resources

```
if not soroban → nil
data = soroban_data()
disk_read = soroban_disk_read_entries(data.resources, data.ext, ...)

→ TransactionResources {
    instructions,
    disk_read_entries, write_entries,
    disk_read_bytes, write_bytes,
    contract_events_size_bytes,
    transaction_size_bytes: inner_tx_size_bytes()
  }
```

---

### TransactionFrame::is_valid_structure

```
GUARD operations is empty          → false
GUARD operations.len > 100         → false
GUARD fee == 0                     → false
GUARD soroban AND operations.len != 1 → false

"stellar-core does NOT enforce envelope size limit during execution.
The 100KB MAX_CLASSIC_TX_SIZE_BYTES limit is applied at the overlay layer."

→ true
```

---

### TransactionFrame::validate_soroban_memo

"Parity: TransactionFrame.cpp:314-342"

```
if not soroban → true
GUARD memo is not MEMO_NONE                 → false
GUARD source_account is MuxedEd25519        → false
for each op in operations:
  GUARD op.source_account is MuxedEd25519   → false
→ true
```

---

### muxed_to_account_id

```
muxed type switch:
  Ed25519(key)      → AccountId(PublicKeyTypeEd25519(key))
  MuxedEd25519(m)   → AccountId(PublicKeyTypeEd25519(m.ed25519))
```

---

### Helper: soroban_disk_read_entries

```
if is_restore_footprint:
  → read_write footprint length

@version(<23):
  → read_only.len + read_write.len

@version(≥23):
  count = 0
  for each key in read_only:
    if not is_soroban_ledger_key(key):
      count += 1
  for each key in read_write:
    if not is_soroban_ledger_key(key):
      count += 1

  if ext is V1:
    count += ext.archived_soroban_entries.len

  → count
```

---

### Helper: is_soroban_ledger_key

```
→ key is ContractData or ContractCode
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~725   | ~210       |
| Functions     | 30     | 28         |
