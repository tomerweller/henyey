## Pseudocode: crates/tx/src/operations/execute/extend_footprint_ttl.rs

"ExtendFootprintTtl operation execution."
"Extends the time-to-live for Soroban contract data entries."

CONST MAX_ENTRY_TTL = 6_312_000  // ~1 year at 5-second ledger close

### execute_extend_footprint_ttl

"Matches stellar-core ExtendFootprintTTLApplyHelper::apply() behavior"

```
function execute_extend_footprint_ttl(op, source, state,
                                       context, soroban_data):

  "--- Validation ---"

  GUARD op.extend_to == 0                        → Malformed
  GUARD op.extend_to > MAX_ENTRY_TTL - 1         → Malformed
  GUARD soroban_data is absent                    → Malformed
  GUARD footprint.read_write is not empty         → Malformed

  for each key in footprint.read_only:
    GUARD key is not ContractData or ContractCode  → Malformed

  "--- Extend TTL for all entries in read-only footprint ---"

  "stellar-core: newLiveUntilLedgerSeq = getLedgerSeq() + extendTo"
  new_live_until = current_ledger + op.extend_to
  accumulated_read_bytes = 0

  for each key in footprint.read_only:
    key_hash = SHA256(XDR(key))

    ttl = state.get_ttl(key_hash)

    "stellar-core: !ttlLeOpt -> continue"
    if ttl not found:
      continue

    "stellar-core: !isLive(*ttlLeOpt, getLedgerSeq()) -> continue"
    if ttl.live_until_ledger_seq < current_ledger:
      continue

    "stellar-core: currLiveUntilLedgerSeq >= newLiveUntilLedgerSeq -> continue"
    if ttl.live_until_ledger_seq >= new_live_until:
      continue

    "stellar-core: releaseAssertOrThrow(entryOpt)"
    entry = state.get_entry(key)
    if entry not found:
      continue

    "stellar-core: checkReadBytesResourceLimit(entrySize)"
    entry_size = XDR_size(entry)
    accumulated_read_bytes += entry_size
    GUARD disk_read_bytes_limit > 0
      AND accumulated_read_bytes > disk_read_bytes_limit
      → ResourceLimitExceeded

    MUTATE state extend_ttl(key_hash, new_live_until)

  → Success
```

### Helper: is_ttl_entry

```
function is_ttl_entry(key):
  → key is ContractData OR ContractCode
```

### Helper: compute_ledger_key_hash

```
function compute_ledger_key_hash(key):
  → SHA256(XDR_encode(key))
```

## Summary
| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 160    | 48         |
| Functions    | 4      | 3          |
