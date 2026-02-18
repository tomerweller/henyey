# Pseudocode: crates/db/src/queries/scp.rs

"SCP consensus state persistence including envelopes, quorum sets,
slot state for crash recovery, and transaction set storage."

## Trait: ScpQueries

### store_scp_history

"Replaces any existing envelopes for the ledger. Envelopes are stored
sorted by node ID for deterministic ordering."

```
function store_scp_history(ledger_seq, envelopes):
    DB DELETE FROM scphistory
        WHERE ledgerseq = ledger_seq

    GUARD envelopes is empty → return

    sort envelopes by node_id_hex(envelope.node_id)
    for each envelope in sorted envelopes:
        node_id = node_id_hex(envelope.node_id)
        data = encode_xdr(envelope)
        DB INSERT INTO scphistory
            (nodeid, ledgerseq, envelope)
            VALUES (node_id, ledger_seq, data)
```

**Calls**: [node_id_hex](#helper-node_id_hex)

### load_scp_history

```
function load_scp_history(ledger_seq)
    -> list of ScpEnvelope:
    rows = DB SELECT envelope FROM scphistory
               WHERE ledgerseq = ledger_seq
               ORDER BY nodeid
    envelopes = []
    for each data in rows:
        envelope = decode_xdr(data) as ScpEnvelope
        append envelope to envelopes
    → envelopes
```

### store_scp_quorum_set

"If the quorum set already exists, only updates the last-seen
ledger sequence if the new value is higher."

```
function store_scp_quorum_set(hash, last_ledger_seq,
                              quorum_set):
    hash_hex = hash.to_hex()
    existing = DB SELECT lastledgerseq FROM scpquorums
                   WHERE qsethash = hash_hex

    if existing is found:
        GUARD existing >= last_ledger_seq → return
        DB UPDATE scpquorums
            SET lastledgerseq = last_ledger_seq
            WHERE qsethash = hash_hex
        → return

    data = encode_xdr(quorum_set)
    DB INSERT INTO scpquorums
        (qsethash, lastledgerseq, qset)
        VALUES (hash_hex, last_ledger_seq, data)
```

### load_scp_quorum_set

```
function load_scp_quorum_set(hash)
    -> ScpQuorumSet or none:
    hash_hex = hash.to_hex()
    data = DB SELECT qset FROM scpquorums
               WHERE qsethash = hash_hex
    GUARD data is none → none
    → decode_xdr(data) as ScpQuorumSet
```

### copy_scp_history_to_stream

"Builds ScpHistoryEntry V0 records for [begin, begin+count) by
combining SCP envelopes and their referenced quorum sets."

```
function copy_scp_history_to_stream(
    begin, count, stream) -> integer:

    end = begin + count  (saturating)
    written = 0

    ledger_seqs = DB SELECT DISTINCT ledgerseq
        FROM scphistory
        WHERE ledgerseq >= begin AND ledgerseq < end
        ORDER BY ledgerseq ASC

    for each ledger_seq in ledger_seqs:
        envelopes = load_scp_history(ledger_seq)
        GUARD envelopes is empty → skip

        "Collect referenced quorum set hashes"
        qset_hashes = set()
        for each env in envelopes:
            hash = scp_envelope_quorum_set_hash(env)
            if hash exists:
                qset_hashes.add(hash)

        "Load referenced quorum sets"
        quorum_sets = []
        for each hash in qset_hashes:
            qset = load_scp_quorum_set(hash)
            if qset exists:
                append qset to quorum_sets

        entry = ScpHistoryEntry::V0 {
            quorum_sets: quorum_sets,
            ledger_messages: {
                ledger_seq: ledger_seq,
                messages: envelopes
            }
        }
        stream.write(entry)
        written += 1

    → written
```

**Calls**: [load_scp_history](#load_scp_history) | [scp_envelope_quorum_set_hash](#helper-scp_envelope_quorum_set_hash) | [load_scp_quorum_set](#load_scp_quorum_set)

### delete_old_scp_entries

"Removes old entries from both scphistory and scpquorums tables.
Used by the Maintainer for garbage collection."

```
function delete_old_scp_entries(max_ledger, count)
    -> integer:
    NOTE: scphistory may have multiple rows per ledger

    history_deleted = DB DELETE FROM scphistory
        WHERE rowid IN (
            SELECT rowid FROM scphistory
            WHERE ledgerseq <= max_ledger
            ORDER BY ledgerseq ASC
            LIMIT count
        )

    "Delete quorum sets no longer referenced"
    quorums_deleted = DB DELETE FROM scpquorums
        WHERE qsethash IN (
            SELECT qsethash FROM scpquorums
            WHERE lastledgerseq <= max_ledger
            ORDER BY lastledgerseq ASC
            LIMIT count
        )

    → history_deleted + quorums_deleted
```

## Helper: scp_envelope_quorum_set_hash

```
function scp_envelope_quorum_set_hash(envelope)
    -> Hash256:
    "Extract quorum set hash from statement pledges"
    if pledges is Nominate:
        hash = pledges.quorum_set_hash
    if pledges is Prepare:
        hash = pledges.quorum_set_hash
    if pledges is Confirm:
        hash = pledges.quorum_set_hash
    if pledges is Externalize:
        hash = pledges.commit_quorum_set_hash
    → Hash256.from_bytes(hash)
```

## Helper: node_id_hex

```
function node_id_hex(node_id) -> string:
    "Convert Ed25519 public key to hex string for
     database storage and deterministic sorting"
    → hex_encode(node_id.ed25519_bytes)
```

---

## Trait: ScpStatePersistenceQueries

"Extended queries for SCP state persistence (crash recovery).
Uses the storestate table with key prefixes."

### save_scp_slot_state

```
function save_scp_slot_state(slot, state_json):
    key = "scpstate:" + slot
    DB INSERT OR REPLACE INTO storestate
        (statename, state) VALUES (key, state_json)
```

### load_scp_slot_state

```
function load_scp_slot_state(slot) -> string or none:
    key = "scpstate:" + slot
    → DB SELECT state FROM storestate
          WHERE statename = key
```

### load_all_scp_slot_states

```
function load_all_scp_slot_states()
    -> list of (slot, json):
    prefix = "scpstate:"
    rows = DB SELECT statename, state FROM storestate
               WHERE statename LIKE prefix + "%"
               ORDER BY statename

    results = []
    for each (key, state) in rows:
        slot_str = key without prefix
        GUARD slot_str not parseable as integer → skip
        slot = parse slot_str as integer
        append (slot, state) to results
    → results
```

### delete_scp_slot_states_below

```
function delete_scp_slot_states_below(slot):
    prefix = "scpstate:"
    rows = DB SELECT statename FROM storestate
               WHERE statename LIKE prefix + "%"

    keys_to_delete = []
    for each key in rows:
        slot_str = key without prefix
        GUARD slot_str not parseable → skip
        key_slot = parse slot_str as integer
        if key_slot < slot:
            append key to keys_to_delete

    for each key in keys_to_delete:
        DB DELETE FROM storestate
            WHERE statename = key
```

### save_tx_set_data

"Store tx set by hash using storestate with 'txset:' prefix,
data is base64-encoded."

```
function save_tx_set_data(hash, data):
    key = "txset:" + hex_encode(hash)
    encoded = base64_encode(data)
    DB INSERT OR REPLACE INTO storestate
        (statename, state) VALUES (key, encoded)
```

### load_tx_set_data

```
function load_tx_set_data(hash)
    -> bytes or none:
    key = "txset:" + hex_encode(hash)
    encoded = DB SELECT state FROM storestate
                  WHERE statename = key
    GUARD encoded is none → none
    data = base64_decode(encoded)
    GUARD decode fails → error "Invalid base64 tx set data"
    → data
```

### load_all_tx_set_data

```
function load_all_tx_set_data()
    -> list of (hash, bytes):
    prefix = "txset:"
    rows = DB SELECT statename, state FROM storestate
               WHERE statename LIKE prefix + "%"

    results = []
    for each (key, encoded) in rows:
        hash_hex = key without prefix
        GUARD hex_decode fails → skip
        GUARD not 32 bytes → skip
        GUARD base64_decode fails → skip
        hash = hash_bytes as Hash
        data = base64_decode(encoded)
        append (hash, data) to results
    → results
```

### has_tx_set_data

```
function has_tx_set_data(hash) -> boolean:
    key = "txset:" + hex_encode(hash)
    count = DB SELECT COUNT(*) FROM storestate
                WHERE statename = key
    → count > 0
```

### delete_old_tx_set_data

```
function delete_old_tx_set_data(slot):
    NOTE: No-op in current implementation. TX sets are
    cleaned up when no longer referenced by any
    persisted slot state.
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 312    | 160        |
| Functions    | 15     | 15         |
