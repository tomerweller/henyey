# CLI Parity Plan: Henyey ↔ stellar-core for stellar-rpc

## Goal

Enable stellar-rpc to use henyey as a drop-in replacement for stellar-core at the CLI level. This covers (1) ensuring henyey's native CLI has all required functionality, and (2) building a compatibility layer so henyey accepts stellar-core's exact CLI syntax and config format.

## Background: What stellar-rpc Actually Invokes

stellar-rpc launches stellar-core as a subprocess ("captive core" mode). The exact invocation sequence depends on the mode:

### Construction-time (always, before any subprocess)

```bash
stellar-core version    # parsed for protocol version number
stellar-core version    # parsed for build version string
```

The Go code (`stellar_core_version.go`) parses:
- **Build version**: first line of `version` output
- **Protocol version**: line matching `ledger protocol version: N`

### Online Mode (live streaming — normal stellar-rpc operation)

```bash
# 1. Check existing DB state
stellar-core --conf <conf> --console offline-info

# 2. If no valid DB exists (first start, or LCL out of range):
stellar-core --conf <conf> --console new-db
stellar-core --conf <conf> --console catchup <from-1>/0

# 3. Always: long-running streaming process
stellar-core --conf <conf> --console run --metadata-output-stream fd:3
```

Decision logic for steps 1-2:
- If `offline-info` fails → create new DB
- If `offline-info` succeeds but LCL ≤ 1 or LCL > `from` → create new DB
- If `offline-info` succeeds and LCL is valid → skip new-db + catchup, go straight to run

### Offline Mode (re-ingestion — bounded replay)

```bash
stellar-core --conf <conf> --console new-db
stellar-core --conf <conf> --console catchup <to>/<count> --metadata-output-stream fd:3
```

Offline mode always uses an ephemeral directory and always creates a fresh DB.

---

## Gap Analysis

| CLI Feature | stellar-core | henyey | Gap? |
|---|---|---|---|
| `version` subcommand | Prints build info + `ledger protocol version: N` | Has `--version` (clap), no `version` subcommand | **YES** |
| `--conf` flag | Global flag for config file path | `--config` / `-c` only | **YES** |
| `--console` flag | Enables console logging | Not present (logs to console by default) | **YES** |
| `offline-info` subcommand | Prints JSON with ledger state from DB | Not present | **YES** |
| `new-db` subcommand | Initializes DB to genesis state (ledger 1) | Creates empty DB file | **VERIFY** |
| `catchup <to>/<count>` format | Positional arg, `count=0` = minimal catchup | Supports this format | **VERIFY** |
| `catchup --metadata-output-stream` | Streams meta during catchup replay | Global flag exists, needs verification | **VERIFY** |
| `run --metadata-output-stream fd:3` | Streams meta during live mode | Already works | OK |
| `--wait-for-consensus` on `run` | Controls `FORCE_SCP` for validators | Not present | **NOT USED** by stellar-rpc |
| `--in-memory` (deprecated) | Accepted, ignored | Not present | **LOW** |
| `--ll` flag | Sets log level | Not present | **LOW** |
| `--metric` flag | Reports metric on exit | Not present | **LOW** |
| Config format (`SCREAMING_CASE`) | Flat top-level `SCREAMING_CASE` TOML | Nested `snake_case` sections | **YES** |
| `DATABASE = "sqlite3://..."` | With `sqlite3://` prefix | Raw path | **YES** (config layer) |
| `[HISTORY.name]` sections | stellar-core format | `[[history.archives]]` format | **YES** (config layer) |

---

## Part 1: Ensure henyey's native CLI covers required functionality

| # | Item | Priority | Description |
|---|------|----------|-------------|
| **1.1** | `version` subcommand with parseable output | **CRITICAL** | stellar-rpc calls `stellar-core version` and parses output for (a) protocol version from `ledger protocol version: N` and (b) build string from first line. |
| **1.2** | `offline-info` subcommand | **CRITICAL** | Opens DB read-only, prints JSON with `{"info":{"ledger":{"num":N,...}}}`. stellar-rpc uses this to check if existing DB can be reused. |
| **1.3** | `new-db` genesis initialization | **CRITICAL** | Verify that after `new-db`, the DB is in a state that catchup can start from. stellar-core initializes to genesis (ledger 1). |
| **1.4** | `catchup` with `count=0` (minimal) | **HIGH** | stellar-rpc calls `catchup <ledger>/0` for minimal catchup. Verify henyey handles `count=0`. |
| **1.5** | `catchup --metadata-output-stream` | **HIGH** | In offline mode, stellar-rpc passes `--metadata-output-stream fd:3` to catchup. Verify meta streaming works during catchup. |

## Part 2: CLI compatibility layer

| # | Item | Priority | Description |
|---|------|----------|-------------|
| **2.1** | `--conf` alias for `--config` | **CRITICAL** | One-line clap change: `#[arg(short, long, alias = "conf")]` |
| **2.2** | `--console` flag accepted silently | **CRITICAL** | Add global `--console` flag, accept and ignore. |
| **2.3** | Config format auto-detection (`compat_config.rs`) | **CRITICAL** | Auto-detect `SCREAMING_CASE` flat TOML → translate to henyey's `AppConfig`. Handles `DATABASE` prefix stripping, `[HISTORY.name]` translation, all key mappings. |
| **2.4** | `version` output format matching | **CRITICAL** | Must include: (1) build string as first line, (2) `ledger protocol version: N`. |
| **2.5** | `offline-info` JSON output format matching | **HIGH** | Output must match stellar-core's format for Go JSON parsing. |
| **2.6** | Deprecated flags accepted silently | **LOW** | `--in-memory`, `--start-at-ledger`, `--start-at-hash`, `--minimal-for-in-memory-mode`. |
| **2.7** | `--ll`, `--metric` flags | **LOW** | Accept and optionally wire. Not used by stellar-rpc. |

---

## Config Compatibility Key Mappings

| stellar-core Key | Henyey Equivalent | Status |
|-------------------|-------------------|--------|
| `METADATA_OUTPUT_STREAM` | `metadata.output_stream` | Exists |
| `HTTP_PORT` | `http.port` | Exists |
| `HTTP_QUERY_PORT` | `query.port` | Exists |
| `QUERY_SNAPSHOT_LEDGERS` | `query.snapshot_ledgers` | Exists |
| `QUERY_THREAD_POOL_SIZE` | `query.thread_pool_size` | Exists |
| `NODE_SEED` | `node.node_seed` | Exists |
| `NODE_IS_VALIDATOR` | `node.is_validator` | Exists |
| `NETWORK_PASSPHRASE` | `network.passphrase` | Exists |
| `PEER_PORT` | `overlay.peer_port` | Exists |
| `KNOWN_PEERS` | `overlay.known_peers` | Exists |
| `PREFERRED_PEERS` | `overlay.preferred_peers` | Exists |
| `DATABASE` | `database.path` | Exists (strip `sqlite3://` prefix) |
| `BUCKET_DIR_PATH` | `buckets.directory` | Exists |
| `CATCHUP_COMPLETE` | `catchup.complete` | Exists |
| `CATCHUP_RECENT` | `catchup.recent` | Exists |
| `UNSAFE_QUORUM` | `node.unsafe_quorum` | May need to add |
| `RUN_STANDALONE` | `node.run_standalone` | May need to add |
| `ENABLE_SOROBAN_DIAGNOSTIC_EVENTS` | `diagnostics.soroban_diagnostic_events` | Exists |
| `ENABLE_DIAGNOSTICS_FOR_TX_SUBMISSION` | `diagnostics.tx_submission_diagnostics` | Exists |
| `EMIT_SOROBAN_TRANSACTION_META_EXT_V1` | `metadata.emit_soroban_tx_meta_ext_v1` | Exists |
| `EMIT_LEDGER_CLOSE_META_EXT_V1` | `metadata.emit_ledger_close_meta_ext_v1` | Exists |
| `[HISTORY.name] get="..."` | `[[history.archives]]` | Exists (syntax differs) |

---

## Implementation Phases

### Phase A — Critical (blocks stellar-rpc integration)

1. **A1**: `--conf` alias + `--console` flag — trivial clap changes
2. **A2**: `version` subcommand with stellar-core-compatible output format
3. **A3**: `offline-info` subcommand — open DB read-only, emit JSON matching stellar-core
4. **A4**: Config compat layer `compat_config.rs` — auto-detect + translate stellar-core TOML

### Phase B — High priority (verify/fix existing behavior)

5. **B1**: Verify `new-db` behavior is sufficient for stellar-rpc
6. **B2**: Verify `catchup <N>/0` minimal mode works
7. **B3**: Verify `catchup` + `--metadata-output-stream` works
8. **B4**: Add deprecated flags (`--in-memory`, `--start-at-ledger`, etc.)

### Phase C — Low priority

9. **C1**: `--ll`, `--metric` flags

---

## Key Insight

`--wait-for-consensus` is **not** used by stellar-rpc. It only matters for validators, and stellar-rpc runs stellar-core in non-validator watcher mode. The real critical gaps are: `version` output format, `offline-info`, `--conf` alias, `--console` flag, and the config compat layer.

## What's Not Needed

- No changes to stellar-rpc
- `--wait-for-consensus` (stellar-rpc doesn't pass it)
- Validator-only features (stellar-rpc uses non-validator mode)
- `force-scp` command (deprecated)
- Test/fuzz subcommands (BUILD_TESTS only in stellar-core)
