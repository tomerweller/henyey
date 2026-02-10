# Quickstart Docker Readiness Analysis

Analysis of what Stellar's [quickstart Docker image](https://github.com/stellar/quickstart)
relies on from stellar-core, and how ready henyey is to serve as a drop-in replacement.

## Quickstart Architecture

The quickstart image runs up to **3 stellar-core instances** simultaneously:

1. **Main validator/watcher node** -- PostgreSQL-backed, managed by supervisord
2. **Horizon captive-core** -- SQLite-backed, spawned by Horizon process
3. **stellar-rpc captive-core** -- SQLite-backed, spawned by stellar-rpc process

Services start in order via supervisord priorities:
postgresql (10) -> stellar-core (20) -> horizon (30) -> friendbot (40) -> nginx (50) -> stellar-rpc (60)

### Port Layout

| Port  | Service                              |
|-------|--------------------------------------|
| 5432  | PostgreSQL                           |
| 8000  | nginx (reverse proxy)                |
| 8001  | Horizon (direct)                     |
| 8002  | Friendbot (direct)                   |
| 8003  | Stellar-RPC (direct, JSON-RPC)       |
| 6060  | Horizon admin                        |
| 6061  | Stellar-RPC admin                    |
| 11625 | stellar-core peer (main)             |
| 11626 | stellar-core HTTP (main)             |
| 11725 | stellar-core peer (Horizon captive)  |
| 11726 | stellar-core HTTP (Horizon captive)  |
| 11825 | stellar-core peer (RPC captive)      |
| 11826 | stellar-core HTTP (RPC captive)      |
| 1570  | Local history archive (Python HTTP)  |

---

## CLI Commands Used by Quickstart

### `stellar-core version`

Prints version at startup.

```bash
stellar-core version 2>/dev/null | sed 's/^/    /'
```

**henyey status:** Missing. clap provides `--version` but no `version` subcommand.

### `stellar-core convert-id <hash>`

Derives root account ID and secret key from the SHA256 hash of the network passphrase.

```bash
stellar-core convert-id $NETWORK_ID | awk -F': ' '/strKey: /{print $2}' | tail -2
```

Output is parsed to extract `NETWORK_ROOT_SECRET_KEY` and `NETWORK_ROOT_ACCOUNT_ID`.

**henyey status:** Missing with these semantics. `offline convert-key` exists but
converts strkeys, not raw SHA256-to-strkey.

### `stellar-core new-db --conf <path>`

Initializes a fresh database. Runs on first initialization only.

```bash
sudo -u stellar stellar-core new-db --conf etc/stellar-core.cfg
```

**henyey status:** Partial. `new-db` exists but uses `--config` (global flag),
not `--conf`. Config format is TOML, not stellar-core `.cfg`.

### `stellar-core force-scp --conf <path>`

Forces SCP to start nominating on next startup. Used for local network only.

```bash
sudo -u stellar stellar-core force-scp --conf $COREHOME/etc/stellar-core.cfg
```

**henyey status:** Missing. No equivalent command.

### `stellar-core new-hist <name> --conf <path>`

Initializes a local history archive. Used for local network only.

```bash
sudo -u stellar stellar-core new-hist vs --conf $COREHOME/etc/stellar-core.cfg
```

**henyey status:** Missing. No equivalent command.

### `stellar-core --conf <path> run`

The long-running node process, managed by supervisord.

```bash
exec /usr/bin/stellar-core --conf "/opt/stellar/core/etc/stellar-core.cfg" run
```

**henyey status:** Partial. `run` exists but config flag is `--config/-c`, not
`--conf`. Config format is TOML, not stellar-core `.cfg`.

### `stellar-core get-settings-upgrade-txs`

Generates signed transactions for upgrading Soroban config settings on local networks.
Secret key piped via stdin.

```bash
echo $NETWORK_ROOT_SECRET_KEY \
  | stellar-core get-settings-upgrade-txs \
    "$NETWORK_ROOT_ACCOUNT_ID" 0 "$NETWORK_PASSPHRASE" \
    --xdr $(stellar-xdr encode --type ConfigUpgradeSet < "$COREHOME/etc/config-settings/...") \
    --signtxs
```

**henyey status:** Missing. No equivalent command.

### CLI Command Summary

| Command                    | henyey | Notes                                      |
|----------------------------|-----------------|---------------------------------------------|
| `version`                  | Missing         | Need subcommand (not just `--version`)      |
| `convert-id`              | Missing         | Different semantics than `offline convert-key` |
| `new-db --conf`           | Partial         | Exists but different flag name + config format |
| `force-scp --conf`        | Missing         | Required for local network                  |
| `new-hist`                | Missing         | Required for local network                  |
| `run` (via `--conf`)      | Partial         | Different flag name + config format         |
| `get-settings-upgrade-txs` | Missing         | Required for local Soroban config upgrades  |

---

## HTTP Endpoints Used by Quickstart

### `GET /info`

Polled to check node state, ledger version after upgrades, and status messages.

```bash
# Wait for readiness
curl -s http://localhost:11626/info | jq -r '.info.state'

# Check protocol version after upgrade
curl -s http://localhost:11626/info | jq -r '.info.ledger.version'

# Status monitoring
curl -s http://localhost:11626/info | jq -r '"\([.info.state] + (.info.status // []) | join("; "))"'
```

Fields consumed: `.info.state`, `.info.ledger.version`, `.info.status[]`

**henyey status:** Partial. Endpoint exists but returns a different JSON shape.
Current response has top-level `version`, `node_name`, `state`, etc. Missing the nested
`.info.ledger.version` and `.info.status` array.

### `GET /upgrades?mode=set&...`

Schedules protocol upgrades and Soroban config upgrades.

```bash
# Protocol + base reserve upgrade
curl -s "http://localhost:11626/upgrades?mode=set&upgradetime=1970-01-01T00:00:00Z&protocolversion=$V&basereserve=5000000"

# Soroban config upgrade
curl -sG 'http://localhost:11626/upgrades?mode=set&upgradetime=1970-01-01T00:00:00Z' \
  --data-urlencode "configupgradesetkey=$key"
```

Parameters: `mode=set`, `upgradetime`, `protocolversion`, `basereserve`, `configupgradesetkey`

**henyey status:** Missing. Only a read-only `GET /upgrades` exists. No
`mode=set` support for scheduling upgrades via HTTP.

### `GET /tx?blob=<xdr>`

Submits encoded transaction blobs via GET query parameter.

```bash
curl -sG 'http://localhost:11626/tx' --data-urlencode "blob=$tx" | jq -r '.status'
```

**henyey status:** Incompatible. `/tx` exists but expects `POST` with JSON body
`{"tx": "<base64>"}`, not `GET` with `blob` query param.

### `GET /metrics`

Reads transaction count metrics to confirm transaction confirmation.

```bash
curl -s http://localhost:11626/metrics | jq -r '.metrics."ledger.transaction.count".count'
```

**henyey status:** Partial. `/metrics` exists but returns Prometheus text format
with different metric names (`stellar_*`), not stellar-core JSON format with
`.metrics."ledger.transaction.count".count`.

### HTTP Endpoint Summary

| Endpoint                  | henyey | Notes                                  |
|---------------------------|-----------------|----------------------------------------|
| `GET /info`               | Partial         | Different JSON shape                   |
| `GET /upgrades?mode=set`  | Missing         | No write/set support                   |
| `GET /tx?blob=`           | Incompatible    | Expects POST + JSON, not GET + query   |
| `GET /metrics`            | Partial         | Prometheus text, not stellar-core JSON format   |

---

## Configuration Compatibility

### Config File Format

stellar-core uses a custom `.cfg` format. henyey uses TOML. These are
**completely incompatible** -- every config file would need to be rewritten or a
compatibility layer added.

stellar-core example:
```
HTTP_PORT=11626
PUBLIC_HTTP_PORT=true
NODE_SEED="SDQVDISRYN2JXBS7ICL7QJAEKB3HWBJFP2QECXG7GZICAHBK4UNJCWK2 self"
NODE_IS_VALIDATOR=true
DATABASE="postgresql://dbname=core host=localhost"
NETWORK_PASSPHRASE="Test SDF Network ; September 2015"
ARTIFICIALLY_ACCELERATE_TIME_FOR_TESTING=true

[QUORUM_SET]
THRESHOLD_PERCENT=100
VALIDATORS=["$self"]

[HISTORY.vs]
get="cp /tmp/stellar-core/history/vs/{0} {1}"
put="cp {0} /tmp/stellar-core/history/vs/{1}"
mkdir="mkdir -p /tmp/stellar-core/history/vs/{0}"
```

henyey TOML equivalent:
```toml
[http]
port = 11626

[node]
node_seed = "SDQVDISRYN2JXBS7ICL7QJAEKB3HWBJFP2QECXG7GZICAHBK4UNJCWK2"
is_validator = true

[database]
path = "stellar.db"

[network]
passphrase = "Test SDF Network ; September 2015"
```

### CLI Flag Name

stellar-core uses `--conf`. henyey uses `--config` / `-c`.

### Config Property Coverage

| stellar-core Config Property                          | henyey    | Status                        |
|----------------------------------------------|--------------------|-------------------------------|
| `HTTP_PORT`                                  | `http.port`        | Present                       |
| `PUBLIC_HTTP_PORT`                           | `http.enabled`     | Present (different semantics) |
| `DATABASE` (PostgreSQL)                      | --                 | **Not supported**             |
| `DATABASE` (SQLite)                          | `database.path`    | Present                       |
| `NETWORK_PASSPHRASE`                         | `network.passphrase` | Present                     |
| `NODE_SEED`                                  | `node.node_seed`   | Present                       |
| `NODE_IS_VALIDATOR`                          | `node.is_validator` | Present                      |
| `MANUAL_CLOSE`                               | `node.manual_close` | Present                      |
| `PEER_PORT`                                  | `overlay.peer_port` | Present                      |
| `EXPERIMENTAL_BUCKETLIST_DB`                 | --                 | Always on (N/A)               |
| `CATCHUP_RECENT`                             | --                 | **Missing** (CLI-only mode)   |
| `ARTIFICIALLY_ACCELERATE_TIME_FOR_TESTING`   | --                 | **Missing**                   |
| `FAILURE_SAFETY`                             | --                 | **Missing**                   |
| `UNSAFE_QUORUM`                              | --                 | **Missing**                   |
| `COMMANDS`                                   | --                 | **Missing**                   |
| `ENABLE_SOROBAN_DIAGNOSTIC_EVENTS`           | --                 | **Missing**                   |
| `ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION`       | --                 | **Missing**                   |
| `LOG_FILE_PATH`                              | --                 | **Missing** (logs to stdout)  |
| `[QUORUM_SET]`                               | `node.quorum_set`  | Present (TOML syntax)         |
| `[HISTORY.*]` with get/put/mkdir commands    | `history.archives` | Present (URL-based, no shell) |

### Database Backend

The **single largest blocker** for the standalone node:

- Quickstart main node uses **PostgreSQL** (`postgresql://dbname=core host=localhost`)
- henyey supports **SQLite only**
- Captive-core instances use SQLite (compatible)
- Horizon has its own PostgreSQL database independent of stellar-core

---

## Captive-Core Integration

Horizon and stellar-rpc spawn stellar-core as a captive-core subprocess. The Go SDK
(`stellar/go/ingest/ledgerbackend`) manages this by:

1. Writing a config file in stellar-core `.cfg` format
2. Running `stellar-core new-db --conf <path>`
3. Running `stellar-core run --conf <path> --metadata-output-stream fd:N`
4. Reading `LedgerCloseMeta` frames from the pipe (fd:N)
5. Polling `/info` for status

| Requirement                        | henyey Status                |
|------------------------------------|---------------------------------------|
| Binary at `STELLAR_CORE_BINARY_PATH` | OK                                  |
| Accepts `--conf <path>`           | **Incompatible** -- uses `--config`   |
| `run` subcommand                   | OK                                    |
| `new-db` subcommand               | OK (different flag style)             |
| SQLite support                     | OK                                    |
| `--metadata-output-stream fd:N`   | OK (just implemented)                 |
| stellar-core `.cfg` config format          | **Incompatible** -- expects TOML      |
| `/info` HTTP response shape       | **Partially incompatible**            |
| `ENABLE_SOROBAN_DIAGNOSTIC_EVENTS` | **Missing** config option             |

The `--metadata-output-stream` feature (including `fd:N` support) is now implemented and
wire-format compatible with stellar-core, which enables the core data flow. However, the config
format and CLI flag names prevent the Go SDK from driving henyey without
modifications to either side.

---

## Readiness Summary

| Category                        | Ready? | Notes                                                        |
|---------------------------------|--------|--------------------------------------------------------------|
| Core ledger close + meta stream | Yes    | Wire-format compatible with stellar-core                              |
| SQLite database                 | Yes    | Fully supported                                              |
| PostgreSQL database             | No     | Not supported; blocker for standalone node                   |
| Config file format              | No     | TOML vs stellar-core `.cfg` -- completely incompatible                |
| CLI flag names                  | No     | `--config` vs `--conf`                                       |
| CLI commands (quickstart needs) | Partial | 3/7 missing, 2/7 partial                                   |
| HTTP API compatibility          | No     | Different response shapes, missing endpoints                 |
| Captive-core integration        | No     | Go SDK writes stellar-core config format and uses `--conf`            |
| Local network support           | No     | Missing `force-scp`, `new-hist`, accelerated time, unsafe quorum |
| Testnet/pubnet watcher          | Partial | Core sync works but config/CLI incompatible                 |
| Protocol upgrades via HTTP      | No     | `/upgrades?mode=set` not implemented                         |
| Transaction submission compat   | No     | `/tx` expects different format                               |

---

## Priority Path to Quickstart Compatibility

### Tier 1 -- Blockers (required for any quickstart integration)

1. **Config compatibility layer** -- either support stellar-core `.cfg` format or provide a
   translation tool; quickstart scripts (and the Go captive-core SDK) generate `.cfg` files
2. **CLI flag alias** -- add `--conf` as an alias for `--config`
3. **`/info` response parity** -- match stellar-core JSON shape: `.info.state`,
   `.info.ledger.version`, `.info.status[]`
4. **`/tx` GET compatibility** -- accept `?blob=<xdr>` query parameter in addition to
   POST JSON

### Tier 2 -- Required for local network (most common quickstart use case)

5. `force-scp` command (or `--wait-for-consensus` run flag)
6. `new-hist` command for initializing local history archives
7. `ARTIFICIALLY_ACCELERATE_TIME_FOR_TESTING` + `UNSAFE_QUORUM` + `FAILURE_SAFETY` config options
8. `/upgrades?mode=set` endpoint for scheduling protocol/config upgrades
9. `convert-id` with network-hash-to-strkey semantics
10. `version` subcommand (not just `--version`)

### Tier 3 -- Required for captive-core swap (Horizon/RPC integration)

11. Go captive-core SDK compatibility (config format + CLI flags + `/info` response)
12. `ENABLE_SOROBAN_DIAGNOSTIC_EVENTS` config option
13. `get-settings-upgrade-txs` command (for Soroban config upgrades on local network)

### Tier 4 -- Nice-to-have

14. PostgreSQL support (only needed if keeping the standalone main node pattern)
15. `CATCHUP_RECENT` config option
16. `/metrics` JSON format parity with stellar-core (currently Prometheus text)

### Recommended Approach

Target the **captive-core use case first** (Tiers 1 + 3). Those instances already use
SQLite, and the quickstart scripts that manage them are simpler. The standalone main node
swap (requiring PostgreSQL or a quickstart restructure) can come later.

Alternatively, the quickstart repository could be modified with a parallel code path that
generates TOML configs and uses `--config` when detecting henyey as the binary.
This avoids adding stellar-core config parsing to the Rust codebase at the cost of quickstart
complexity.
