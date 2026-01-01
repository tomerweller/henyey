# Parity Matrix: stellar-core v25.0.1 vs rs-stellar-core

Scope: SQLite only; Protocol 23+ only; no production hardening.
Baseline: `/Users/tomer/dev/stellar-core` @ v25.0.1

Legend: Present / Partial / Missing

## Core Application

| Upstream | Key files (v25) | rs-stellar-core mapping | Status | Notes |
| --- | --- | --- | --- | --- |
| main | `Application.*`, `CommandHandler.*`, `Config.*`, `QueryServer.*`, `Diagnostics.*` | `crates/rs-stellar-core` | Partial | CLI + config + HTTP endpoints present; application lifecycle + diagnostics + command handler parity missing. |
| process | `ProcessManager.*` | (none) | Missing | No process lifecycle manager. |
| util | `src/util/*` | `crates/stellar-core-common` | Partial | Basic types/utils only; upstream util covers more runtime utilities. |

## Work Scheduling

| Upstream | Key files (v25) | rs-stellar-core mapping | Status | Notes |
| --- | --- | --- | --- | --- |
| work | `WorkScheduler.*`, `Work.*`, `WorkSequence.*` | `crates/stellar-core-work` | Partial | Scheduler, cancellation, metrics, and graph introspection implemented; app metrics export wiring still missing. |
| historywork | `GetHistoryArchiveStateWork.*`, `DownloadBucketsWork.*`, `VerifyBucketWork.*`, `PublishWork.*` | `crates/stellar-core-historywork` | Partial | Download/verify + publish work implemented with progress polling (HAS/buckets/headers/tx/results/SCP); metrics export wiring and replay integration pending. |

## Ledger / Transactions

| Upstream | Key files (v25) | rs-stellar-core mapping | Status | Notes |
| --- | --- | --- | --- | --- |
| ledger | `LedgerManager.*`, `LedgerTxn.*`, `LedgerCloseMetaFrame.*`, `LedgerHeaderUtils.*` | `crates/stellar-core-ledger` | Partial | Ledger close pipeline present; tx result hash computed; fee-bump results handled; generalized tx set base-fee overrides honored; ledger close meta v2 + per-op/tx meta produced; ledger txn layering still partial. |
| transactions | `TransactionFrame.*`, `OperationFrame.*`, `ParallelApply*`, `TransactionMeta.*` | `crates/stellar-core-tx` | Partial | Core ops implemented; signature/fee/sequence/time/ledger-bounds validation; signer weight checks for Ed25519, preauth, hashX, signed payload; preconditions V2 min-seq/age/gap/extra signers supported; tx meta hash normalization + short hash implemented, golden vectors pending. |
| herder | `Herder.*`, `TxQueue*`, `Upgrades.*`, `QuorumTracker.*` | `crates/stellar-core-herder` | Partial | Tx queue + SCP coordination present; generalized tx set caching/responses wired into ledger close; SCP upgrades now fed into ledger close with proposal support; quorum set exchange + on-demand requests wired; basic quorum tracker wired (slot-level quorum/v-blocking), full parity pending. |

## Consensus / Overlay / History

| Upstream | Key files (v25) | rs-stellar-core mapping | Status | Notes |
| --- | --- | --- | --- | --- |
| scp | `SCP.*`, `Slot.*`, `BallotProtocol.*`, `NominationProtocol.*` | `crates/stellar-core-scp` | Partial | Core SCP logic present; deterministic priority/value hashing and timeout wiring in place; edge-case semantics still pending. |
| overlay | `OverlayManager.*`, `Peer*`, `FlowControl.*`, `Survey*`, `TxAdverts.*` | `crates/stellar-core-overlay` | Partial | Basic P2P + auth present; flow control + rate limiting + handshake gating present; preferred/target outbound connector loop implemented; peer discovery list updated from Peers messages with periodic peer advertising and persisted to SQLite for startup seeding; config known/preferred peers reset backoff on startup; peer backoff/failure tracking persisted with exponential jitter, private/local peers filtered (including ingest filtering), excessive failures pruned (configurable), known peer list refreshed from config + SQLite cache (periodically), connect attempts randomized, peer lists capped at 50 entries, discovery stops at outbound target/capacity, DB-backed random peer selection for outbound/preferred is implemented, peer records track inbound/outbound with preferred/outbound preserved on inbound observations, peer addresses use Hello listening_port, IPv6 peers are ignored, and Peers advertisements use DB-backed inbound/outbound/preferred lists with outbound prioritized, max-failures=10, and no backoff filtering; time-sliced survey topology responses encrypted/decrypted with survey data manager (deltas + lost sync count + ping-based avg latency + p75 SCP latencies) plus limiter/throttle and flood-gate duplicate suppression; tx advert/demand parity wired (per-peer queues, randomized demand scheduling, backoff, retry); survey reporting backlog + command endpoints wired (permissions based on local quorum set if configured). Automatic survey scheduling is unsupported to match upstream. |
| history | `HistoryArchive.*`, `HistoryManager.*`, `CatchupManager.*` | `crates/stellar-core-history` | Partial | Archive access + catchup present; historywork used for checkpoint download; replay re-executes tx sets and verifies tx result hash; catchup persists history + bucket list snapshots + SCP history; publish CLI writes local archives and supports put/mkdir command templates for remote archives. |

## Invariants / Simulation / Testing

| Upstream | Key files (v25) | rs-stellar-core mapping | Status | Notes |
| --- | --- | --- | --- | --- |
| invariant | `InvariantManager.*`, `ConservationOfLumens.*`, `LedgerEntryIsValid.*` | `crates/stellar-core-invariant` | Partial | Framework + basic invariants wired to ledger close and replay; missing full invariant set + advanced checks. |
| simulation | `Simulation.*`, `LoadGenerator.*`, `TxGenerator.*` | `crates/stellar-core-simulation` | Partial | Overlay simulation harness + basic test; load/tx generators missing. |
| test | `src/test/*` | (none) | Missing | No upstream-style test harness or fixtures. |

## Protocol / Data

| Upstream | Key files (v25) | rs-stellar-core mapping | Status | Notes |
| --- | --- | --- | --- | --- |
| protocol-curr/next | `src/protocol-curr`, `src/protocol-next` | `stellar-xdr` | Partial | XDR types present; upgrade mechanisms not mirrored. |
| database | `src/database/*` | `crates/stellar-core-db` | Partial | SQLite only; schema subset. |

## Integration Tests (rs-stellar-core)

| Area | Test | Status |
| --- | --- | --- |
| history | `crates/stellar-core-history/tests/catchup_integration.rs` | Present |
| ledger | `crates/stellar-core-ledger/tests/ledger_close_integration.rs` | Present |
| ledger | `crates/stellar-core-ledger/tests/transaction_execution.rs` | Present |
| overlay/SCP | `crates/stellar-core-overlay/tests/overlay_scp_integration.rs` | Present |
