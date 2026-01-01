# v25 Parity Plan (rs-stellar-core)

Baseline: stellar-core v25.0.1
Scope constraints: SQLite only; protocol 23+ only; no production hardening; no Postgres.

## Parity Matrix (v25.0.1)

See `docs/PARITY_MATRIX.md` for the validated matrix and status notes.

## Implementation Plan

### Phase 0: Parity Matrix Validation
- Enumerate v25.0.1 public interfaces and key behaviors per module.
- Identify exact rs-stellar-core gaps and classify as missing vs partial.
- Output: validated matrix + issue list with ownership and acceptance criteria.

### Phase 1: Work Scheduler Core (work/)
- Introduce a work engine crate (or module) with job queue, dependencies, retries, and metrics.
- Define work traits for history, overlay, ledger close, and publish.
- Wire into rs-stellar-core app lifecycle.
- Output: scheduler tests; basic metrics; deterministic shutdown.

### Phase 2: Historywork Pipeline
- Implement catchup/publish work items driven by scheduler.
- Provide checkpoint pipeline: download HAS, buckets, verify, replay.
- Integrate with ledger initialization + DB state.
- Output: end-to-end catchup work with progress + error handling.

### Phase 3: Invariants Framework
- Define invariant traits + registry.
- Implement core v25 invariants (bucket list hash, entry consistency, balance invariants).
- Integrate into ledger close and replay paths.
- Output: invariant failures surfaced in logs/metrics, gating in tests.

### Phase 4: Simulation + Regression Harness
- Add deterministic multi-node simulation support (overlay + SCP + herder + ledger).
- Add load generation hooks and scenario runners.
- Output: basic scenario suite (happy path, slow node, fork resolution).

### Phase 5: Core Behavioral Parity
- Ledger close meta parity (tx result hash now computed in ledger close).
- Transaction validation order + error mapping parity (baseline validation + fee-bump handling in place).
- Soroban storage mutations (including deletes) parity.
- Overlay flow control + peer management parity with v25 expectations.

### Phase 6: CLI/Admin/Process Parity (within scope)
- Expand CLI to match v25 operational commands where feasible.
- Add lifecycle hooks (signals, state transitions, health checks).
- Output: operational parity checklist.

## Acceptance Criteria
- All Phase 1-6 items have integration tests.
- Catchup + replay + ledger close produce hashes that match v25 for the same inputs.
- Overlay + SCP reach externalization in simulation runs.
- All invariants pass for standard test scenarios.

## Test Coverage Roadmap
- Catchup: checkpoint-only + replay range.
- Ledger close: empty tx set + mixed ops + soroban.
- Overlay/SCP: multi-node message roundtrip + flow control.
- Regression: deterministic replay with golden vectors.
