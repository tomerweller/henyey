## Pseudocode: crates/history/src/verify.rs

"Cryptographic verification utilities for history data."
"Verification layers: header chain, bucket hash, tx set, bucket list hash."

### Data Structures

```
VerificationResult:
  headers_verified: u32
  buckets_verified: u32
  ledgers_verified: u32
  final_ledger_hash: Hash256
```

### verify_header_chain

"Ledger headers form a cryptographic hash chain where each header"
"contains previous_ledger_hash — the SHA-256 hash of the previous header."

```
function verify_header_chain(headers):
  GUARD headers is empty → ok (nothing to verify)

  for i in 1..length(headers):
    prev_header = headers[i - 1]
    curr_header = headers[i]

    GUARD curr_header.ledger_seq != prev_header.ledger_seq + 1
      → InvalidSequence

    prev_hash = compute_header_hash(prev_header)
    expected_prev_hash = curr_header.previous_ledger_hash

    GUARD prev_hash != expected_prev_hash
      → InvalidPreviousHash(curr_header.ledger_seq)
```

### verify_bucket_hash

"Each bucket file is identified by its SHA-256 content hash."

```
function verify_bucket_hash(data, expected_hash):
  actual_hash = SHA256(data)
  GUARD actual_hash != expected_hash
    → "bucket hash mismatch"
```

### verify_ledger_hash

"The computed bucket list hash must match header.bucket_list_hash."

```
function verify_ledger_hash(header, bucket_list_hash):
  header_bucket_hash = header.bucket_list_hash
  GUARD header_bucket_hash != bucket_list_hash
    → "bucket list hash mismatch at ledger N"
```

### compute_header_hash

"Compute the SHA-256 hash of a ledger header."
"This is stored in the next ledger's previous_ledger_hash."

```
function compute_header_hash(header):
  xdr_bytes = header.to_xdr()
  → SHA256(xdr_bytes)
```

### verify_tx_result_set

"The hash of the transaction result set must match the header."
"For genesis ledger (seq == 1), empty result set is accepted"
"without hash verification, matching stellar-core VerifyTxResultsWork."

```
function verify_tx_result_set(header, tx_result_set_xdr):
  GUARD header.ledger_seq == GENESIS_LEDGER_SEQ
        and tx_result_set_xdr is empty → ok (skip)

  actual_hash = SHA256(tx_result_set_xdr)
  expected_hash = header.tx_set_result_hash

  GUARD actual_hash != expected_hash
    → "tx result set hash mismatch at ledger N"
```

### compute_tx_set_hash

"Compute transaction set hash according to protocol rules."

```
function compute_tx_set_hash(tx_set):
  if tx_set is Classic:
    hasher = new SHA256
    hasher.update(tx_set.previous_ledger_hash)
    for each tx in tx_set.txs:
      hasher.update(tx.to_xdr())
    → hasher.finalize()

  if tx_set is Generalized:
    bytes = tx_set.to_xdr()
    → SHA256(bytes)
```

### verify_tx_set

"The tx set hash in the SCP value must match the downloaded tx set."

```
function verify_tx_set(header, tx_set):
  actual_hash = compute_tx_set_hash(tx_set)
  expected_hash = header.scp_value.tx_set_hash

  GUARD actual_hash != expected_hash
    → InvalidTxSetHash(header.ledger_seq)
```

### verify_header_matches_trusted

"Verify downloaded header against a header received via SCP consensus."

```
function verify_header_matches_trusted(downloaded_header,
    trusted_header):
  GUARD downloaded_header.ledger_seq != trusted_header.ledger_seq
    → InvalidSequence

  downloaded_hash = compute_header_hash(downloaded_header)
  trusted_hash = compute_header_hash(trusted_header)

  GUARD downloaded_hash != trusted_hash
    → "header hash mismatch at ledger N"
```

### verify_has_structure

"Verify the History Archive State structure is well-formed."

```
function verify_has_structure(has):
  GUARD has.current_buckets is empty
    → "HAS has no bucket levels"

  GUARD has.version < 1 or has.version > 2
    → "unsupported HAS version"
```

### verify_has_checkpoint

```
function verify_has_checkpoint(has, expected):
  GUARD has.current_ledger != expected
    → "HAS checkpoint mismatch"
```

### verify_scp_history_entries

"Verify SCP history entries contain quorum sets for all referenced envelopes."

```
function verify_scp_history_entries(entries):
  for each entry in entries:
    v0 = entry.v0
    qset_hashes = set()
    for each qset in v0.quorum_sets:
      qset_hashes.add(SHA256_XDR(qset))

    for each envelope in v0.ledger_messages.messages:
      hash = scp_quorum_set_hash(envelope.statement)
      if hash is not null:
        GUARD hash not in qset_hashes
          → "missing quorum set in scp history"
```

### verify_tx_result_ordering

"Verify that tx result entries within a checkpoint are correctly ordered."
"All ledger sequence numbers must fall within checkpoint range"
"and be strictly increasing."

```
function verify_tx_result_ordering(entries, checkpoint):
  GUARD entries is empty → ok

  (range_start, range_end) = checkpoint_range(checkpoint)
  prev_seq = null

  for each entry in entries:
    GUARD entry.ledger_seq < range_start
          or entry.ledger_seq > range_end
      → "tx result entry outside checkpoint range"

    if prev_seq is not null:
      GUARD entry.ledger_seq <= prev_seq
        → "tx result entries not strictly increasing"

    prev_seq = entry.ledger_seq
```

### Helper: scp_quorum_set_hash

```
function scp_quorum_set_hash(statement):
  if statement is Nominate:
    → statement.quorum_set_hash
  if statement is Prepare:
    → statement.quorum_set_hash
  if statement is Confirm:
    → statement.quorum_set_hash
  if statement is Externalize:
    → statement.commit_quorum_set_hash
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~385   | ~120       |
| Functions     | 12     | 12         |
