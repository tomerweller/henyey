## Pseudocode: crates/henyey/src/bin/header_compare.rs

"Header comparison utility for debugging ledger hash mismatches.
Compares ledger headers between a local database and a history archive."

### CLI Structure

```
CLI "header_compare":
  --ledger N           "Ledger sequence number to compare"
  --config FILE        "Config file (default: testnet-validator.toml)"
  --db PATH            "Optional database path override"
  --compare-results    "Also compare transaction result sets"
```

### main

```
args = parse CLI
config = AppConfig.from_file_with_env(args.config)

--- Load local header from DB ---
db_path = args.db or config.database.path
db = Database.open(db_path)
local_header = db.get_ledger_header(args.ledger)
GUARD missing → error "missing ledger header in db"
local_hash = compute_header_hash(local_header)

--- Load archive header ---
archive = first enabled archive from config
GUARD none enabled → error "no enabled history archives"
archive = HistoryArchive.new(archive.url)
checkpoint = checkpoint_containing(args.ledger)
headers = archive.get_ledger_headers(checkpoint)
archive_header = find header where ledger_seq == args.ledger
GUARD not found → error "not found in archive"
archive_hash = compute_header_hash(archive_header)

--- Display comparison ---
print_header("local", local_header, local_hash)
print_header("archive", archive_header, archive_hash)

if local_hash == archive_hash:
  print "Hashes match"
else:
  print "Hashes differ"

if --compare-results:
  compare_tx_results(db, archive, ledger, checkpoint)
```

**Calls**: [compute_header_hash](henyey_ledger#compute_header_hash) | [print_header](#print_header) | [compare_tx_results](#compare_tx_results)

---

### print_header

"Displays all relevant header fields for comparison."

```
print label:
  hash, prev_hash, ledger_version, ledger_seq,
  close_time, tx_set_hash, tx_result_hash,
  bucket_list_hash, total_coins, fee_pool,
  inflation_seq, base_fee, base_reserve,
  max_tx_set_size, id_pool, upgrades count
```

---

### compare_tx_results

"Fetches and compares transaction results from local DB and archive."

```
local_entry = db.get_tx_result_entry(ledger)
GUARD missing → error

archive_entries = archive.get_results(checkpoint)
archive_entry = find where ledger_seq == ledger
GUARD not found → error

print_tx_result_hash("local", local_entry)
print_tx_result_hash("archive", archive_entry)

if result counts differ:
  print count mismatch

count = min(local count, archive count)
for i in 0..count:
  local_xdr = serialize local_results[i]
  archive_xdr = serialize archive_results[i]

  if local_xdr != archive_xdr:
    print tx[i] mismatch:
      local fee, result code
      archive fee, result code
```

**Calls**: [print_tx_result_hash](#helper-print_tx_result_hash)

---

### Helper: print_tx_result_hash

```
bytes = serialize entry.tx_result_set to XDR
hash = Hash256.hash(bytes)
print "{label} hash: {hash}"
```

---

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~170   | ~60        |
| Functions     | 4      | 4          |
