# Pseudocode: crates/db/src/queries/bucket_list.rs

"The bucket list is a Merkle tree structure that stores all ledger entries.
At checkpoint ledgers (every 64 ledgers), the bucket hashes are saved
to enable state reconstruction during catchup.

Each level contains two buckets:
  curr — current bucket being filled with new entries
  snap — snapshot of the previous level's merged state"

## Trait: BucketListQueries

### store_bucket_list

```
function store_bucket_list(ledger_seq, levels):
    DB DELETE FROM bucketlist WHERE ledgerseq = ledger_seq
    for each (index, (curr, snap)) in levels:
        DB INSERT INTO bucketlist
            (ledgerseq, level, currhash, snaphash)
            VALUES (ledger_seq, index, curr.hex, snap.hex)
```

### load_bucket_list

```
function load_bucket_list(ledger_seq)
    -> list of (Hash256, Hash256) or none:

    rows = DB SELECT level, currhash, snaphash
               FROM bucketlist
               WHERE ledgerseq = ledger_seq
               ORDER BY level ASC

    entries = []
    for each (level, curr_hex, snap_hex) in rows:
        curr_hash = parse_hash(curr_hex)
        GUARD parse fails → error "Invalid curr hash"
        snap_hash = parse_hash(snap_hex)
        GUARD parse fails → error "Invalid snap hash"
        append (level, curr_hash, snap_hash) to entries

    GUARD entries is empty → none

    "Verify level continuity"
    levels = []
    for each (index, (level, curr, snap)) in entries:
        GUARD level != index
            → error "bucket list level gap at ledger_seq"
        append (curr, snap) to levels

    → levels
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 67     | 28         |
| Functions    | 2      | 2          |
