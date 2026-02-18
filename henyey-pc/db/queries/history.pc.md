# Pseudocode: crates/db/src/queries/history.rs

"Transaction history queries including individual transaction records,
transaction sets per ledger (txsets), and transaction results per
ledger (txresults). Used for history archive publishing and catchup."

## Struct: TxRecord

```
struct TxRecord:
    tx_id       — transaction hash, hex-encoded
    ledger_seq  — ledger where included
    tx_index    — position within the ledger's tx set
    body        — XDR-encoded transaction envelope
    result      — XDR-encoded transaction result
    meta        — XDR-encoded transaction metadata (optional)
```

## Trait: HistoryQueries

### store_transaction

```
function store_transaction(ledger_seq, tx_index, tx_id,
                           body, result, meta):
    DB INSERT OR REPLACE INTO txhistory
        (txid, ledgerseq, txindex, txbody, txresult, txmeta)
        VALUES (tx_id, ledger_seq, tx_index,
                body, result, meta)
```

### load_transaction

```
function load_transaction(tx_id) -> TxRecord or none:
    → DB SELECT ledgerseq, txindex, txbody, txresult, txmeta
          FROM txhistory WHERE txid = tx_id
      mapped to TxRecord
      (returns none if row absent)
```

### store_tx_history_entry

```
function store_tx_history_entry(ledger_seq, entry):
    data = encode_xdr(entry)
    DB INSERT OR REPLACE INTO txsets
        (ledgerseq, data) VALUES (ledger_seq, data)
```

### load_tx_history_entry

```
function load_tx_history_entry(ledger_seq)
    -> TransactionHistoryEntry or none:
    data = DB SELECT data FROM txsets
               WHERE ledgerseq = ledger_seq
    GUARD data is none → none
    → decode_xdr(data) as TransactionHistoryEntry
```

### store_tx_result_entry

```
function store_tx_result_entry(ledger_seq, entry):
    data = encode_xdr(entry)
    DB INSERT OR REPLACE INTO txresults
        (ledgerseq, data) VALUES (ledger_seq, data)
```

### load_tx_result_entry

```
function load_tx_result_entry(ledger_seq)
    -> TransactionHistoryResultEntry or none:
    data = DB SELECT data FROM txresults
               WHERE ledgerseq = ledger_seq
    GUARD data is none → none
    → decode_xdr(data) as TransactionHistoryResultEntry
```

### copy_tx_history_to_streams

"Writes TransactionHistoryEntry records to tx_stream and
TransactionHistoryResultEntry records to result_stream for
ledger sequences [begin, begin+count)."

```
function copy_tx_history_to_streams(
    begin, count, tx_stream, result_stream)
    -> (tx_written, result_written):

    end = begin + count  (saturating)
    tx_written = 0
    result_written = 0

    "Phase 1: Stream transaction history entries"
    rows = DB SELECT data FROM txsets
               WHERE ledgerseq >= begin
                 AND ledgerseq < end
               ORDER BY ledgerseq ASC
    for each data in rows:
        entry = decode_xdr(data) as TransactionHistoryEntry
        tx_stream.write(entry)
        tx_written += 1

    "Phase 2: Stream transaction result entries"
    rows = DB SELECT data FROM txresults
               WHERE ledgerseq >= begin
                 AND ledgerseq < end
               ORDER BY ledgerseq ASC
    for each data in rows:
        entry = decode_xdr(data)
            as TransactionHistoryResultEntry
        result_stream.write(entry)
        result_written += 1

    → (tx_written, result_written)
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 156    | 67         |
| Functions    | 7      | 7          |
