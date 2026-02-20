# Feasibility Analysis: Henyey as stellar-rpc Backend

## Overview

This document evaluates the feasibility of using Henyey as a drop-in replacement
for stellar-core when running stellar-rpc (Soroban RPC). The goal is to eliminate
the C++ dependency by having RPC spawn Henyey instead of stellar-core.

## stellar-rpc's 4 Integration Points with stellar-core

| Interface | Mechanism | Purpose | Henyey Status |
|-----------|-----------|---------|---------------|
| **1. Meta Pipe** | Named pipe (`METADATA_OUTPUT_STREAM`) | Streams `LedgerCloseMeta` XDR for ingestion | Partial |
| **2. HTTP Command** | `POST /tx`, `GET /info`, etc. on port 11626 | Transaction submission, node status | Mostly ready |
| **3. HTTP Query** | `POST /getledgerentryraw` on query port | Ledger entry retrieval by key | Not implemented |
| **4. Preflight FFI** | CGO -> Rust `libpreflight` -> `soroban-simulation` | Transaction simulation | Not applicable (bypasses core) |

## Interface-by-Interface Breakdown

### 1. Metadata Streaming (Named Pipe)

**What RPC needs:** stellar-core writes `xdr::LedgerCloseMeta` frames to a named
pipe. The Go-side `CaptiveStellarCore` reads one ledger at a time.

**Henyey today:** Generates `LedgerCloseMeta` during ledger close, but writes it
to internal consumers, not a named pipe.

**Gap:** Add a `METADATA_OUTPUT_STREAM` config option and a writer that serializes
`LedgerCloseMeta` XDR to the pipe fd. This is straightforward -- serialize XDR,
write to file descriptor on each ledger close.

**Effort: Low-Medium**

### 2. HTTP Command Server

**What RPC needs:**
- `POST /tx?blob=<base64>` -> submit transaction, return `{status: PENDING|ERROR|DUPLICATE|...}`
- `GET /info` -> protocol version, ledger number, sync state
- `POST /manualclose` -> force ledger close (testing)

**Henyey today:** Already has `/tx`, `/info`, `/manualclose`, `/status` endpoints.
The response format may differ from stellar-core's JSON schema.

**Gap:** Verify and align JSON response schemas with what the Go `stellarcore.Client`
expects. The `/tx` response in particular needs exact field names (`status`, `error`,
`diagnostic_events`).

**Effort: Low** -- mostly schema alignment, not new functionality.

### 3. HTTP Query Server (`/getledgerentryraw`)

**What RPC needs:** `POST /getledgerentryraw` with `ledgerSeq=N&key=<base64 LedgerKey XDR>`
(supports multiple keys). Returns raw base64 `LedgerEntry` XDR with state
(live/archived/not-found) and `liveUntilLedgerSeq` for TTL entries. Must support
querying against recent historical snapshots (`QUERY_SNAPSHOT_LEDGERS`).

**Henyey today:** Has bucket list with full ledger state, but no HTTP endpoint
exposing raw entry lookups. The bucket list supports point lookups internally.

**Gap:** This is the biggest new feature needed. Requires:
- New HTTP endpoint with stellar-core-compatible request/response format
- Snapshot management (retaining N recent ledger snapshots for queries)
- Thread pool for concurrent query handling
- TTL resolution for Soroban entries

**Effort: Medium-High** -- new endpoint + snapshot infrastructure.

### 4. Preflight / Transaction Simulation

**What RPC needs:** CGO bridge to Rust `soroban-simulation` crate. This runs
entirely within the RPC process -- it calls *back* into Go to fetch ledger entries
(which then hit the query server).

**Henyey impact:** None directly. The preflight system uses `soroban-simulation`
(a standalone Rust crate), not stellar-core. It only needs ledger entries, which
it gets via the query server (#3 above). If Henyey serves `/getledgerentryraw`
correctly, preflight works unchanged.

## Captive Core Process Lifecycle

**What RPC expects:** It spawns stellar-core as a subprocess with:
1. A generated TOML config (sets `METADATA_OUTPUT_STREAM`, `HTTP_PORT`, `HTTP_QUERY_PORT`, etc.)
2. A command: either `catchup <from>/<count>` (bounded replay) or `run` (live streaming)
3. It monitors the process, reads from the pipe, and hits HTTP endpoints

**What Henyey needs:**
- Accept the same TOML config keys RPC generates (or a compatible subset)
- Support the same CLI invocation pattern: `henyey catchup ...` and `henyey run ...`
  with the pipe/port config
- The existing `catchup` and `run` commands are close but need the pipe output and
  config compatibility

**Effort: Medium** -- CLI/config compatibility layer.

## Effort Estimates

| Component | Feasibility | Effort | Risk |
|-----------|------------|--------|------|
| Meta pipe output | High | ~1 week | Low -- well-defined XDR format |
| HTTP command schema alignment | High | ~2-3 days | Low -- mostly JSON formatting |
| `/getledgerentryraw` endpoint | Medium-High | ~2-3 weeks | Medium -- snapshot management is new |
| CLI/config compatibility | High | ~1 week | Low -- config parsing |
| **Total harness** | **Feasible** | **~4-6 weeks** | **Medium overall** |

## Recommended Approach: Core Harness

Rather than modifying RPC, build a compatibility harness in Henyey that makes it a
drop-in replacement for `stellar-core` from RPC's perspective:

1. **Config compatibility layer** -- Parse the TOML that RPC generates (map
   `METADATA_OUTPUT_STREAM`, `HTTP_PORT`, `HTTP_QUERY_PORT`, `QUERY_SNAPSHOT_LEDGERS`
   to Henyey config)
2. **Meta pipe writer** -- On each ledger close, serialize `LedgerCloseMeta` to the
   configured pipe path
3. **HTTP schema alignment** -- Ensure `/tx`, `/info` response JSON matches Go client
   expectations
4. **`/getledgerentryraw` endpoint** -- New endpoint backed by bucket list lookups
   with snapshot retention
5. **CLI entry point compatibility** -- Ensure `henyey run` and `henyey catchup`
   accept the flags RPC passes

## Key Advantages

- **Preflight is free** -- `soroban-simulation` is already Rust; it only needs
  ledger entry access via the query endpoint
- **No Go code changes needed** -- RPC just swaps the binary path from `stellar-core`
  to `henyey`
- **Henyey already has most of the core logic** -- SCP, ledger close, transaction
  execution, bucket list, HTTP server are all implemented
- **Pure Rust stack** -- Eliminates the C++ dependency chain entirely

## Key Risks

- **Response schema mismatches** -- The Go `stellarcore.Client` may parse specific
  JSON fields that Henyey formats differently. Needs careful testing against the Go
  client's deserialization.
- **Snapshot query correctness** -- `/getledgerentryraw` must return entries at exact
  ledger boundaries. Bucket list state must be queryable at historical snapshots,
  which is new infrastructure.
- **Edge cases in captive mode** -- Process lifecycle management (graceful shutdown
  signals, pipe buffering, error reporting) needs to match what the Go side expects.

## Verdict

This is feasible and well-scoped. The hardest piece is `/getledgerentryraw` with
snapshot support. Everything else is compatibility plumbing around functionality
Henyey already has.
