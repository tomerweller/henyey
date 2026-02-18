## Pseudocode: crates/herder/src/ledger_close_data.rs

"Ledger close data for consensus output."
"Encapsulates all information needed to close a ledger after SCP consensus."

### Data: LedgerCloseData

```
LedgerCloseData:
  ledger_seq:            u32
  tx_set:                TransactionSet
  value:                 StellarValue
  expected_ledger_hash:  Hash256 or null
```

### new

```
function new(ledger_seq, tx_set, value, expected_ledger_hash):
  ASSERT: tx_set.hash == value.tx_set_hash
    "Transaction set hash mismatch"

  → LedgerCloseData {
      ledger_seq, tx_set, value, expected_ledger_hash
    }
```

### Accessors

```
function ledger_seq():  → self.ledger_seq
function tx_set():      → self.tx_set
function value():       → self.value
function expected_hash(): → self.expected_ledger_hash
function close_time():  → self.value.close_time
function upgrades():    → self.value.upgrades
function tx_set_hash(): → self.tx_set.hash
```

### to_xdr

```
function to_xdr():
  → StoredDebugTransactionSet {
      tx_set:     self.tx_set.to_xdr_stored_set(),
      scp_value:  self.value,
      ledger_seq: self.ledger_seq
    }
```

**Calls:** [`TransactionSet::to_xdr_stored_set`](tx_queue/tx_set.pc.md#to_xdr_stored_set)

### from_xdr

```
function from_xdr(sts):
  tx_set = TransactionSet.from_xdr_stored_set(sts.tx_set)
  GUARD tx_set is error → TxSetDecodeError

  GUARD tx_set.hash != sts.scp_value.tx_set_hash
    → TxSetHashMismatch

  → LedgerCloseData {
      ledger_seq: sts.ledger_seq,
      tx_set:     tx_set,
      value:      sts.scp_value,
      expected_ledger_hash: null
    }
```

**Calls:** [`TransactionSet::from_xdr_stored_set`](tx_queue/tx_set.pc.md#from_xdr_stored_set)

### validate_hash

```
function validate_hash(actual_hash):
  if self.expected_ledger_hash is null:
    → true
  → self.expected_ledger_hash == actual_hash
```

### stellar_value_to_string

"Matches stellar-core stellarValueToString function."

```
function stellar_value_to_string(sv, short_node_id_fn):
  res = "["

  if sv.ext is Signed:
    if short_node_id_fn is not null:
      res += " SIGNED@" + short_node_id_fn(sig.node_id)
    else:
      res += " SIGNED"

  short_hash = hex(sv.tx_set_hash)[0..8]
  res += " txH: " + short_hash
  res += ", ct: " + sv.close_time

  res += ", upgrades: ["
  for each (i, upgrade) in sv.upgrades:
    if i > 0:
      res += ", "
    if upgrade is empty:
      res += "<empty>"
    else:
      parsed = decode_xdr(LedgerUpgrade, upgrade)
      if parsed is ok:
        res += upgrade_to_string(parsed)
      else:
        res += "<unknown>"
  res += " ] ]"

  → res
```

### Helper: upgrade_to_string

```
function upgrade_to_string(upgrade):
  if upgrade is Version(v):      → "version=" + v
  if upgrade is BaseFee(f):      → "baseFee=" + f
  if upgrade is MaxTxSetSize(s): → "maxTxSetSize=" + s
  if upgrade is BaseReserve(r):  → "baseReserve=" + r
  if upgrade is Flags(f):        → "flags=" + f
  if upgrade is Config(c):
    short_hash = hex(c.content_hash)[0..8]
    → "config(hash=" + short_hash + ")"
  if upgrade is MaxSorobanTxSetSize(s):
    → "maxSorobanTxSetSize=" + s
```

### Error: LedgerCloseDataError

```
LedgerCloseDataError:
  TxSetHashMismatch   — tx set hash != StellarValue tx_set_hash
  TxSetDecodeError    — failed to decode transaction set
  XdrError            — XDR encoding/decoding failure
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 233    | 78         |
| Functions     | 13     | 10         |
