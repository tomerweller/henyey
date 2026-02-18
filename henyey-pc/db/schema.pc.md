# Pseudocode: crates/db/src/schema.rs

Database schema definitions and well-known state keys.

## CREATE_SCHEMA

Complete SQL schema for a fresh database:

```
TABLES:
    storestate          (statename PK, state)
        "Key-value store for node configuration"

    ledgerheaders       (ledgerhash PK, prevhash, bucketlisthash,
                         ledgerseq UNIQUE, closetime, data BLOB)
        INDEX: ledgerheaders_seq ON ledgerseq

    txhistory           (txid PK, ledgerseq, txindex,
                         txbody BLOB, txresult BLOB, txmeta BLOB)
        INDEX: txhistory_ledger ON ledgerseq

    txsets              (ledgerseq PK, data BLOB)

    txresults           (ledgerseq PK, data BLOB)

    bucketlist          (ledgerseq + level PK,
                         currhash, snaphash)
        INDEX: bucketlist_ledger ON ledgerseq

    scphistory          (nodeid, ledgerseq, envelope BLOB)
        INDEX: scphistory_ledger ON ledgerseq

    scpquorums          (qsethash PK, lastledgerseq, qset BLOB)

    peers               (ip + port PK, nextattempt,
                         numfailures DEFAULT 0, type)

    ban                 (nodeid PK)

    publishqueue        (ledgerseq PK, state)
```

## state_keys

Well-known keys for the `storestate` table:

```
CONST LAST_CLOSED_LEDGER   = "lastclosedledger"
    // primary chain progress indicator
CONST HISTORY_ARCHIVE_STATE = "historyarchivestate"
    // JSON-encoded last published checkpoint
CONST DATABASE_SCHEMA       = "databaseschema"
    // schema version for migration tracking
CONST NETWORK_PASSPHRASE    = "networkpassphrase"
    // identifies which Stellar network
CONST LEDGER_UPGRADE_VERSION = "ledgerupgradeversion"
    // pending protocol upgrade target
CONST LAST_SCP_DATA         = "lastscpdata"
    // serialized SCP state for crash recovery
CONST SCP_STATE             = "scpstate"
    // current SCP nomination/ballot state
```

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 128    | 48         |
| Functions    | 0      | 0          |
