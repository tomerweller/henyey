# Pseudocode: crates/db/src/migrations.rs

"Migrations are applied sequentially, one version at a time. Each migration
is executed in a transaction to ensure atomicity. If a migration fails,
the database is left in its previous state."

CONST CURRENT_VERSION = 5

## Migration Registry

```
MIGRATIONS:
    v1 → v2: "Add txsets and txresults tables"
        CREATE txsets (ledgerseq PK, data BLOB)
        CREATE txresults (ledgerseq PK, data BLOB)

    v2 → v3: "Add bucket list table"
        CREATE bucketlist (ledgerseq + level PK,
            currhash, snaphash)
        INDEX bucketlist_ledger ON ledgerseq

    v3 → v4: "Add publish queue table"
        CREATE publishqueue (ledgerseq PK, state)

    v4 → v5: "Allow multiple SCP envelopes per node/ledger"
        RENAME scphistory → scphistory_old
        CREATE scphistory (nodeid, ledgerseq,
            envelope BLOB)
        INDEX scphistory_ledger ON ledgerseq
        COPY scphistory_old → scphistory
        DROP scphistory_old
```

### get_schema_version

```
function get_schema_version(conn) -> integer:
    value = DB SELECT state FROM storestate
                WHERE statename = 'databaseschema'
    if no row found:
        "No schema version recorded — assume version 1"
        → 1
    GUARD parse fails → error "Invalid schema version"
    → parsed integer
```

### set_schema_version

```
function set_schema_version(conn, version):
    DB INSERT OR REPLACE INTO storestate
        (statename, state)
        VALUES ('databaseschema', version as string)
```

### needs_migration

```
function needs_migration(conn) -> boolean:
    current = get_schema_version(conn)
    → current < CURRENT_VERSION
```

**Calls**: [get_schema_version](#get_schema_version)

### run_migrations

```
function run_migrations(conn):
    current_version = get_schema_version(conn)

    GUARD current_version == CURRENT_VERSION → return
    GUARD current_version > CURRENT_VERSION
        → error "Database newer than supported"

    while current_version < CURRENT_VERSION:
        migration = find MIGRATIONS where
            from_version == current_version
        GUARD migration not found
            → error "No migration from version N"

        tx = conn.begin_transaction()
        tx.execute(migration.upgrade_sql)
        set_schema_version(tx, migration.to_version)
        tx.commit()

        current_version = migration.to_version
```

**Calls**: [get_schema_version](#get_schema_version) | [set_schema_version](#set_schema_version)

### verify_schema

```
function verify_schema(conn):
    version = get_schema_version(conn)
    GUARD version < CURRENT_VERSION
        → error "schema too old, run migrations first"
    GUARD version > CURRENT_VERSION
        → error "schema newer than software supports"
```

**Calls**: [get_schema_version](#get_schema_version)

### initialize_schema

```
function initialize_schema(conn):
    conn.execute(CREATE_SCHEMA)
    set_schema_version(conn, CURRENT_VERSION)
```

**Calls**: [set_schema_version](#set_schema_version)

## Summary

| Metric       | Source | Pseudocode |
|--------------|--------|------------|
| Lines (logic)| 150    | 56         |
| Functions    | 5      | 5          |
