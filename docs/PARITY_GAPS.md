# Parity Gaps (v25.0.1)

Scope constraints: SQLite only; Protocol 23+ only; no production hardening.

## Milestones

1. Join public testnet as a validator.
2. Join public mainnet as a validator.
3. Full parity with stellar-core C++ (v25.x).

Notes:
- Full invariant coverage is deferred to Milestone 3.

## Missing Subsystems (Must Add)

1. Work scheduler (core orchestration)
   - Upstream: `src/work/*` (`WorkScheduler`, `WorkSequence`, `BasicWork`, `BatchWork`)
   - Status: Partial (scheduler + sequences + callbacks in `crates/stellar-core-work`)
   - Needed: app-level metrics export wiring.

2. Historywork pipeline
   - Upstream: `src/historywork/*` (download, verify, publish work)
   - Status: Partial (download/verify + publish work in `crates/stellar-core-historywork`, including SCP history)
   - Needed: metrics export wiring and replay integration.

3. Invariants framework
   - Upstream: `src/invariant/*` (`InvariantManager`, `ConservationOfLumens`, `LedgerEntryIsValid`)
   - Status: Partial (framework + basic invariants + ledger-close hook)
   - Needed: full invariant set, config/metrics wiring (Milestone 3). Replay invariants now enforced during catchup re-execution.

4. Simulation harness
   - Upstream: `src/simulation/*` (`Simulation`, `LoadGenerator`, `TxGenerator`)
   - Status: Partial (overlay simulation scaffold + multi-node overlay tests in `crates/stellar-core-simulation`)
   - Needed: deterministic multi-node runs, load/tx generators, assertions.

5. Process lifecycle
   - Upstream: `src/process/*` (`ProcessManager`)
   - Needed: process lifecycle, signal handling, state transitions.

6. Test harness + fixtures
   - Upstream: `src/test/*`, `src/testdata/*`
   - Needed: integration/system tests and golden vectors.

## Partial Areas (Need Expansion)

- Application core: add diagnostics, command handler parity, and admin utilities.
- Ledger close: tx meta now includes fee changes in tx_changes_before; full ledger txn layering still partial vs upstream.
- Tx meta hash normalization + short hash implemented; upstream golden-vector validation still needed (synthetic vectors added).
- Soroban: footprint handling parity (storage deletions applied).
- Overlay: surveys + peer manager parity (flow control + rate limiting in place); survey reporting/backlog commands wired with manual scheduling/permissions parity.
- Overlay: peer discovery list now persisted in SQLite and seeded at startup; config known/preferred peers reset backoff on startup; backoff/failure tracking persisted, discovery respects backoff/private-address filtering (including ingest filtering), excessive failures are pruned (configurable), known peer list is refreshed from config + SQLite cache (periodically too), connect attempts are randomized, peer lists are capped at 50 entries, discovery stops at outbound target/capacity, DB-backed random peer selection for outbound/preferred is implemented, peer records track inbound/outbound with preferred/outbound preserved on inbound observations, peer addresses use Hello listening_port, IPv6 peers are ignored, and Peers advertisements use DB-backed inbound/outbound/preferred lists with outbound prioritized, max-failures=10, and no backoff filtering.
- Overlay: automatic survey scheduler is unsupported (manual /survey endpoints only) to match upstream.
- Overlay: tx advert/demand parity complete (per-peer queues, retry scheduling, backoff).
- Overlay: peer manager scheduling parity now matches upstream manual behavior (auto scheduling unsupported).
- Overlay: survey scheduling parity now matches upstream manual flow; automatic scheduling remains unsupported to match upstream.
- Herder: upgrade pipeline + quorum tracking + parallel tx set builder parity.
- SCP timeouts use linear backoff with 30m cap and SCP timing config (protocol 23+); edge-case parity still pending.
- History publish: tx sets/results + bucket list snapshots + SCP history persisted; publish CLI writes local archives and supports put/mkdir command templates for remote archives.

## Suggested Milestones

M1 (Testnet validator): ledger tx layering parity, full op coverage, catchup/replay parity, basic invariants enabled.
M2 (Mainnet validator): performance/soak validation, operational runbooks/config hygiene, mainnet-specific config validation.
M3 (Full parity): full invariant set, simulation harness, regression suite + golden vectors, remaining util/process parity.
