# Pseudocode: crates/db/src/queries/ledger.rs

"Ledger headers contain the metadata for each closed ledger including
sequence numbers, timestamps, hashes, and protocol version information."

## Trait: LedgerQueries

### load_ledger_header

```
function load_ledger_header(seq) -> LedgerHeader or none:
    data = DB SELECT data FROM ledgerheaders
               WHERE ledgerseq = seq
    GUARD data is none → none
    header = decode_xdr(data) as LedgerHeader
    → header
```

### store_ledger_header

```
function store_ledger_header(header, raw_data):
    ledger_hash = hash(raw_data)
    prev_hash = header.previous_ledger_hash
    bucket_list_hash = header.bucket_list_hash

    DB INSERT OR REPLACE INTO ledgerheaders
        (ledgerhash, prevhash, bucketlisthash,
         ledgerseq, closetime, data)
        VALUES (ledger_hash.hex, prev_hash.hex,
                bucket_list_hash.hex,
                header.ledger_seq,
                header.scp_value.close_time,
                raw_data)
```

### get_latest_ledger_seq

```
function get_latest_ledger_seq() -> integer or none:
    → DB SELECT MAX(ledgerseq) FROM ledgerheaders
      (returns none when table is empty)
```

### get_ledger_hash

```
function get_ledger_hash(seq) -> Hash256 or none:
    hex = DB SELECT ledgerhash FROM ledgerheaders
              WHERE ledgerseq = seq
    GUARD hex is none → none
    hash = parse_hash(hex)
    GUARD parse fails → error "Invalid ledger hash"
    → hash
```

### load_ledger_header_by_hash

```
function load_ledger_header_by_hash(hash_hex)
    -> LedgerHeader or none:
    data = DB SELECT data FROM ledgerheaders
               WHERE ledgerhash = hash_hex
    GUARD data is none → none
    header = decode_xdr(data) as LedgerHeader
    → header
```

### copy_ledger_headers_to_stream

"Writes LedgerHeaderHistoryEntry records for ledger sequences
[begin, begin+count) to the XDR output stream."

```
function copy_ledger_headers_to_stream(
    begin, count, stream) -> integer:
    end = begin + count  (saturating)

    rows = DB SELECT ledgerseq, ledgerhash, data
               FROM ledgerheaders
               WHERE ledgerseq >= begin
                 AND ledgerseq < end
               ORDER BY ledgerseq ASC

    written = 0
    for each (seq, hash_hex, data) in rows:
        header = decode_xdr(data) as LedgerHeader
        hash = parse_hash(hash_hex)
        GUARD parse fails → error "Invalid ledger hash"
        entry = LedgerHeaderHistoryEntry {
            hash: hash,
            header: header,
            ext: V0
        }
        stream.write(entry)
        written += 1
    → written
```

### delete_old_ledger_headers

"Used by the Maintainer to garbage collect old ledger history."

```
function delete_old_ledger_headers(max_ledger, count)
    -> integer:
    "SQLite doesn't support LIMIT in DELETE,
     use a subquery"
    deleted = DB DELETE FROM ledgerheaders
        WHERE ledgerseq IN (
            SELECT ledgerseq FROM ledgerheaders
            WHERE ledgerseq <= max_ledger
            ORDER BY ledgerseq ASC
            LIMIT count
        )
    → deleted
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 143    | 63         |
| Functions    | 7      | 7          |
