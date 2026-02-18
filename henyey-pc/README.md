# henyey pseudocode

Language-agnostic pseudocode representation of **Henyey**, a Rust re-implementation of stellar-core v25 (protocol 24+). Generated as a companion to the [stellar-core-pc](https://github.com/tomerweller/stellar-core-pc) pseudocode repository for cross-reference and parity analysis.

This repository mirrors the crate structure of `crates/*/src/`, with each `.rs` production file translated into a `.pc.md` pseudocode file. The pseudocode captures logic flow, guard checks, state mutations, protocol version branches, and cross-file call graphs — while stripping away Rust-specific syntax (Result/Option/match, lifetimes, Arc/Rc/Box, trait impls).

**219 files** across **14 crates**.

## Crates

| Crate | Files | Description |
|-------|------:|-------------|
| [app](app/) | 16 | Application lifecycle, CLI commands, configuration, catchup orchestration, and ledger close coordination |
| [bucket](bucket/) | 21 | Append-only hierarchical BucketList for cumulative ledger state, merging, indexing, snapshots, and hot archive |
| [common](common/) | 12 | Shared types, safe math, protocol version helpers, asset handling, XDR streaming, and network configuration |
| [crypto](crypto/) | 11 | Hashing (SHA-256), Ed25519/Curve25519 keys, signatures, sealed boxes, and StrKey encoding |
| [db](db/) | 15 | SQLite connection pooling, schema migrations, and typed query modules for all persistent data |
| [henyey](henyey/) | 3 | Binary entry point, CLI subcommands, and quorum intersection analysis |
| [herder](herder/) | 26 | Coordination between SCP consensus, transaction queue/mempool, ledger, and overlay network |
| [history](history/) | 16 | Checkpoint management, history archive publishing, downloading, catchup, replay, and verification |
| [historywork](historywork/) | 1 | Async work items for downloading and uploading history archive data |
| [ledger](ledger/) | 16 | Ledger close lifecycle, state deltas, execution pipeline, Soroban state, and bucket list management |
| [overlay](overlay/) | 17 | Peer-to-peer networking: TCP connections, authenticated messaging, flood control, topology surveys |
| [scp](scp/) | 15 | Stellar Consensus Protocol: nomination, ballot protocol, quorum operations, and slot management |
| [tx](tx/) | 49 | Transaction lifecycle, all operation types (classic + Soroban), DEX engine, state management, validation |
| [work](work/) | 1 | Async work scheduler with dependency-aware state machine |

## Pseudocode Conventions

The pseudocode uses a consistent set of conventions across all files:

| Convention | Meaning |
|------------|---------|
| `GUARD condition → result` | Early return on failure, listed in exact source order |
| `MUTATE target field += value` | Explicit write to ledger state |
| `ASSERT: invariant` | Runtime invariant check (panic on violation) |
| `@version(≥N):` / `@version(<N):` | Protocol version conditional branches |
| `CONST NAME = value` | Named constant with semantic meaning |
| `NOTE: text` | Non-obvious context or design rationale |
| `"quoted text"` | Comment imported from the original source |
| `STATE_MACHINE:` | Enum-based state machine definition with transitions |
| `REF: File::function` | Cross-file function reference |

Each function's pseudocode is in a fenced code block, followed by a **Calls** line (outside the block) linking to referenced functions within the same file or across files.

## Source

Generated from the [Henyey](https://github.com/tomerweller/henyey) Rust codebase, targeting stellar-core v25 parity (protocol 24+).
