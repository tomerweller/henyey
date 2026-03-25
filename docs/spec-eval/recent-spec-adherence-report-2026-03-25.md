# Recent Stellar Spec Changes Adherence Report

Date: 2026-03-25
Repository: `henyey`
Spec baseline reviewed: `stellar-specs` commits `2516d0f` and `244b056`

## Scope

This report evaluates henyey against the recent spec changes introduced by:

- `2516d0f` `Update specs for stellar-core v25.2.2`
- `244b056` `Update specs for recent stellar-core fixes`

Each change is classified as:

- **Adherent**: implementation appears to match the updated spec.
- **Partially adherent**: some matching behavior exists, but important parts are missing or weaker than the spec.
- **Non-adherent**: implementation materially diverges from the updated spec.
- **Not implemented / unclear**: no implementation found, or behavior may live outside the Rust code inspected.

## Executive Summary

| Spec change | Status |
|---|---|
| Overlay protocol range v38-v39 | Partially adherent |
| `GET_SCP_STATE` rate limiting (10/window) | Non-adherent |
| Negative `baseFee` rejection in tx-set validation | Partially adherent |
| `computePerOpFee` division-by-zero guard | Adherent |
| Genesis-adjacent close-time relaxation | Partially adherent |
| Sorted pool-share trustline keys before revocation | Non-adherent |
| Tx-set fee-source affordability | Partially adherent |
| Soroban create-contract pairing validation | Non-adherent |
| Stale-snapshot eviction / modified live-entry handling | Partially adherent |
| Catchup corrupt-header classification | Partially adherent |
| Catchup replay retry + resume from current LCL | Partially adherent |

High-risk gaps are concentrated in overlay throttling, trustline revocation ordering, create-contract validation, and tx-set validation strictness.

---

## 1. Overlay protocol range v38-v39

**Spec change**
- The overlay version range advanced from `v35-v38` to `v38-v39`.

**Status**
- **Partially adherent**

**Evidence**
- `crates/overlay/src/lib.rs:574` sets `OVERLAY_VERSION: u32 = 38`
- `crates/overlay/src/lib.rs:575` sets `OVERLAY_MIN_VERSION: u32 = 35`
- `crates/overlay/src/auth.rs:333` emits those values in `Hello`
- `crates/overlay/src/auth.rs:375` only rejects peers whose `overlay_version < local.overlay_min_version`

**Assessment**
- Henyey still advertises `38/35`, not the updated `38/39` range.
- Incoming compatibility checks are weaker than the spec model: there is a lower-bound check, but no explicit handling of the peer-advertised min/max range that would enforce the tightened compatibility window.
- This is not a total interoperability failure, but it is behind the updated spec.

**Impact**
- Henyey may accept peers older than the new minimum.
- Henyey does not accurately advertise the current supported overlay range.

---

## 2. `GET_SCP_STATE` rate limiting (10 requests per window)

**Spec change**
- `GET_SCP_STATE` must be subject to a dedicated per-peer rate limit with a cap of 10 requests per window.

**Status**
- **Non-adherent**

**Evidence**
- `crates/app/src/app/lifecycle.rs:1067` handles `StellarMessage::GetScpState` by immediately calling `send_scp_state`
- `crates/app/src/app/consensus.rs:471` serves SCP state without a request counter around this path
- `crates/overlay/src/flood.rs:47` defines only a generic `DEFAULT_RATE_LIMIT_PER_SEC = 1000`
- `crates/overlay/src/manager.rs` applies a generic inbound limiter, not a `GET_SCP_STATE`-specific peer/window cap

**Assessment**
- I found no dedicated `GET_SCP_STATE` limiter, no per-peer request accounting, and no cap of 10 requests.
- The generic message limiter is not an adequate match for the spec change.

**Impact**
- Henyey is vulnerable to excess `GET_SCP_STATE` traffic relative to the updated protocol behavior.
- Behavior diverges materially from stellar-core and the current spec.

---

## 3. Reject negative `baseFee` in tx-set validation

**Spec change**
- Generalized tx-set components/phases with negative `baseFee` must be rejected as invalid, not normalized away.

**Status**
- **Partially adherent**

**Evidence**
- `crates/ledger/src/close.rs:367` converts component `base_fee` via `u32::try_from(fee).ok()`
- `crates/ledger/src/close.rs:375` does the same for parallel-phase `base_fee`
- Negative values therefore become `None`, not validation failures

**Assessment**
- Henyey does not preserve negative values, but it also does not reject them.
- Instead, malformed negative fees silently degrade to "no explicit fee override", which is weaker than the updated spec.

**Impact**
- Malformed generalized tx-sets may be accepted when they should be rejected.
- This is a tx-set validation parity gap.

---

## 4. `computePerOpFee` division-by-zero guard

**Spec change**
- Per-operation fee computations must guard against zero operation counts.

**Status**
- **Adherent**

**Evidence**
- `crates/herder/src/tx_queue/mod.rs:272` computes `fee_per_op` with `if op_count > 0 { ... } else { 0 }`
- `crates/herder/src/tx_queue/mod.rs:366` does the same in `envelope_fee_per_op`
- `crates/herder/src/tx_queue_limiter.rs:543` uses the same guard in tests/helpers

**Assessment**
- I did not find a Rust function literally named `computePerOpFee`, but the relevant fee-per-op logic in henyey already guards against division by zero.
- This matches the spirit and observable behavior of the spec change.

---

## 5. Genesis-adjacent close-time relaxation

**Spec change**
- Close-time bounds are relaxed for genesis-adjacent nodes in specific non-next-ledger cases.

**Status**
- **Partially adherent**

**Evidence**
- `crates/herder/src/herder.rs:875-877` computes `enforce_recent = tracking_consensus_index <= GENESIS_LEDGER_SEQ` for non-tracking envelope filtering
- `crates/herder/src/herder.rs:877` applies this only in the non-tracking prefilter path
- `crates/herder/src/scp_driver.rs:576` `check_close_time` still enforces strict monotonicity and future-bound checks with no explicit genesis exception

**Assessment**
- Henyey contains a genesis-adjacent relaxation in the early herder prefilter.
- The deeper SCP driver close-time validation path remains strict.
- This looks like a partial implementation of the spec change rather than full end-to-end parity.

**Impact**
- Some genesis-adjacent slow-node scenarios may still be rejected in henyey when stellar-core would accept them.

---

## 6. Sorted pool-share trustline keys before revocation

**Spec change**
- Pool-share trustline keys discovered during asset deauthorization must be processed in canonical sorted order.

**Status**
- **Non-adherent**

**Evidence**
- `crates/tx/src/operations/execute/trust_flags.rs:465` collects pool-share trustlines via `find_pool_share_trustlines_for_asset`
- `crates/tx/src/operations/execute/trust_flags.rs:470` iterates them directly with `for (pool_id, tl_asset) in pool_share_tl_keys`
- `crates/tx/src/operations/execute/trust_flags.rs:676-698` builds the vector by iterating `state.trustlines_iter()` and pushing matches
- `state.trustlines_iter()` is backed by in-memory hash-map iteration, not sorted canonical ordering

**Assessment**
- I found no sorting step before revocation/redeem processing.
- This is a determinism-sensitive mismatch against the updated spec.

**Impact**
- The order of claimable balance creation / pool-share revocation side effects may differ across implementations.
- This is a real consensus-risk parity issue if multiple matching trustlines exist.

---

## 7. Tx-set fee-source affordability

**Spec change**
- Tx-set construction/validation must reject sets where grouped transactions for a fee source are not jointly affordable.

**Status**
- **Partially adherent**

**Evidence**
- Queue-side aggregate fee tracking exists in `crates/herder/src/tx_queue/mod.rs:1256-1287`
- Execution-time affordability is enforced in `crates/ledger/src/execution/mod.rs:881` and `crates/ledger/src/execution/mod.rs:2245-2249`
- Pre-deduction across phases exists in `crates/ledger/src/execution/tx_set.rs:565`
- I did not find a tx-set validation phase that rejects a generalized tx-set up front because a fee source cannot afford all grouped fees in the set

**Assessment**
- Henyey has equivalent protections in the mempool and during execution.
- But the new spec requires a tx-set construction/validation rule, not just eventual execution-time failure.
- That makes current behavior only partially aligned.

**Impact**
- Henyey may accept or prepare tx-sets that stellar-core would now reject earlier.
- This can affect tx-set validity and nomination behavior.

---

## 8. Soroban create-contract pairing validation

**Spec change**
- `CreateContract`/`CreateContractV2` must enforce valid `contractIDPreimage` / `executable` pairings:
  - `FROM_ASSET -> STELLAR_ASSET`
  - `FROM_ADDRESS -> WASM`

**Status**
- **Non-adherent**

**Evidence**
- Soroban structural validation in `crates/tx/src/validation.rs:479` covers resource fields and archived entry rules, but not create-contract pairing
- `crates/tx/src/frame.rs:680` validates Soroban memo/muxed-account constraints only
- `crates/tx/src/operations/execute/invoke_host_function.rs` and `crates/tx/src/soroban/host.rs` pass host functions through to execution, but I found no Rust-side pairing check

**Assessment**
- I found no explicit Rust implementation of the pairing rule.
- It is possible the host library rejects these combinations later, but that would not satisfy the new Rust-visible admission/validation requirement documented in the spec.

**Impact**
- Henyey may admit malformed create-contract transactions longer than stellar-core does.
- This is a direct parity gap in Soroban validation behavior.

---

## 9. Stale-snapshot eviction and modified live-entry handling

**Spec change**
- Eviction resolution must not evict stale snapshot candidates whose live entry was modified in the current ledger, and this condition should be treated as an internal consistency failure.

**Status**
- **Partially adherent**

**Evidence**
- `crates/bucket/src/eviction.rs` resolves candidates using only `modified_ttl_keys`
- `crates/ledger/src/manager.rs` and `crates/history/src/replay.rs` mirror the TTL-based filtering model
- I found no live-entry-key invalidation path analogous to the new spec text

**Assessment**
- Henyey already implements the stale-snapshot/background-scan model and filters candidates whose TTL was modified.
- The newly documented stronger rule around modified live/data entries does not appear to be implemented.

**Impact**
- A stale snapshot candidate whose live entry changed but TTL did not may still be evicted.
- That leaves a correctness/parity gap in eviction resolution.

---

## 10. Catchup corrupt-header classification

**Spec change**
- Runtime/parsing failures while verifying downloaded ledger-header material must be classified as `ERR_CORRUPT_HEADER` and treated as history corruption.

**Status**
- **Partially adherent**

**Evidence**
- `crates/history/src/verify.rs` verifies header sequences and previous-hash links
- `crates/history/src/error.rs` has coarse error classes like `VerificationFailed`, `InvalidPreviousHash`, `InvalidSequence`, `XdrParsing`
- `crates/history/src/error.rs:171` marks multiple verification failures as fatal catchup failures

**Assessment**
- Henyey has robust verification failure handling, but not a dedicated `ERR_CORRUPT_HEADER`-style classification matching the new spec.
- Corrupt downloaded header material appears to collapse into broader fatal verification errors instead of a distinct category.

**Impact**
- Operator diagnostics and retry policy cannot precisely distinguish corrupt archive material from other verification failures.

---

## 11. Catchup replay retry and resume from current LCL

**Spec change**
- Transaction replay should retry a few times and, on retry, resume from `current LCL + 1` rather than the original replay-range start.

**Status**
- **Partially adherent**

**Evidence**
- `crates/app/src/app/catchup_impl.rs:105-179` supports replay-oriented catchup from the current LCL when bucket state already exists
- `crates/app/src/app/catchup_impl.rs:31-39` blocks future catchups after fatal verification failures
- I did not find a dedicated replay-worker retry loop with a bounded `RETRY_A_FEW`-style policy and a clear resume cursor tied to replay failure

**Assessment**
- Henyey does have coarse replay-from-current-LCL behavior at the catchup orchestration level.
- But it does not appear to implement the newly specified replay retry/resume semantics as a dedicated mechanism.
- In particular, verification failures are treated as fatal rather than retriable-from-current-state archive corruption cases.

**Impact**
- Catchup behavior is less resilient than the updated spec.
- Recovery from replay failures is coarser and may require manual intervention sooner than stellar-core.

---

## Priority Findings

### Highest priority non-adherence

1. **`GET_SCP_STATE` rate limiting**
   - Missing dedicated per-peer 10/window limiter.
   - Relevant paths: `crates/app/src/app/lifecycle.rs`, `crates/app/src/app/consensus.rs`, `crates/overlay/src/flood.rs`

2. **Pool-share trustline sorting before revocation**
   - Missing canonical ordering step.
   - Relevant path: `crates/tx/src/operations/execute/trust_flags.rs`

3. **Soroban create-contract pairing validation**
   - Missing explicit validation rule.
   - Relevant paths: `crates/tx/src/validation.rs`, `crates/tx/src/frame.rs`, `crates/tx/src/operations/execute/invoke_host_function.rs`

### Medium priority parity gaps

4. **Negative `baseFee` rejection**
   - Needs explicit invalidation rather than silent fallback.
   - Relevant path: `crates/ledger/src/close.rs`

5. **Tx-set fee-source affordability in validation**
   - Current protections exist, but too late in the pipeline.
   - Relevant paths: `crates/herder/src/tx_queue/mod.rs`, `crates/ledger/src/execution/mod.rs`

6. **Stale-snapshot eviction live-entry invalidation**
   - TTL invalidation exists; live-entry invalidation missing.
   - Relevant path: `crates/bucket/src/eviction.rs`

### Lower priority / more nuanced gaps

7. **Overlay version range advertisement / validation**
8. **Genesis-adjacent close-time relaxation completeness**
9. **Catchup corrupt-header classification**
10. **Catchup replay retry/resume semantics**

---

## Recommended Next Steps

1. Add a dedicated per-peer `GET_SCP_STATE` request limiter matching the new spec.
2. Sort pool-share trustline keys in canonical `LedgerKey` order before revocation/redeem processing.
3. Add explicit Soroban create-contract pairing validation during transaction admission/validation.
4. Tighten generalized tx-set validation so negative `baseFee` is rejected, not ignored.
5. Add tx-set-level grouped fee-source affordability validation before apply.
6. Extend eviction resolution to invalidate or hard-fail candidates whose live entry key was modified in the current ledger.
7. Refine catchup error taxonomy and replay retry behavior to match the new spec more closely.

## Implementation Checklist

### Priority 0: Consensus-critical parity gaps

- [ ] Add a dedicated `GET_SCP_STATE` rate limiter.
  - Files: `crates/app/src/app/lifecycle.rs`, `crates/app/src/app/consensus.rs`, likely `crates/overlay/src/manager.rs` or peer state.
  - Required behavior: track requests per peer in a rolling window, cap at 10, silently ignore or drop excess requests per spec.
  - Validation: add unit/integration coverage for 10 accepted requests and the 11th rejected within the same window.

- [ ] Sort pool-share trustline revocation targets in canonical order before processing.
  - Files: `crates/tx/src/operations/execute/trust_flags.rs`.
  - Required behavior: sort the collected `(pool_id, TrustLineAsset)` list using canonical `LedgerKey` ordering before redeem/deletion side effects.
  - Validation: add a regression test with multiple matching pool-share trustlines whose hash-map iteration order would otherwise vary.

- [ ] Add explicit Soroban create-contract pairing validation.
  - Files: `crates/tx/src/validation.rs`, possibly `crates/tx/src/frame.rs`.
  - Required behavior:
    - `CONTRACT_ID_PREIMAGE_FROM_ASSET -> CONTRACT_EXECUTABLE_STELLAR_ASSET`
    - `CONTRACT_ID_PREIMAGE_FROM_ADDRESS -> CONTRACT_EXECUTABLE_WASM`
    - reject other pairings with `txSOROBAN_INVALID`
  - Validation: add focused tests for both valid pairings and both invalid cross-pairings.

### Priority 1: Tx-set validity parity gaps

- [ ] Reject generalized tx-sets with negative `baseFee`.
  - Files: `crates/ledger/src/close.rs` and any upstream tx-set validation entrypoint.
  - Required behavior: treat negative component/phase `baseFee` as malformed/invalid rather than converting it to `None`.
  - Validation: add tests for negative classic-phase component fees and negative parallel-phase fees.

- [ ] Add tx-set-level grouped fee-source affordability validation.
  - Files: likely `crates/herder`, `crates/ledger/src/close.rs`, or tx-set preparation/validation code.
  - Required behavior: after per-tx validation, group by fee source, sum full fees, and reject all transactions for underfunded fee sources at tx-set validation time.
  - Validation: add tests where transactions are individually valid but jointly unaffordable.

### Priority 2: Ledger-close and eviction correctness gaps

- [ ] Extend eviction resolution to consider modified live entries, not just TTL keys.
  - Files: `crates/bucket/src/eviction.rs`, callers in `crates/ledger/src/manager.rs` and `crates/history/src/replay.rs`.
  - Required behavior: if a stale-snapshot eviction candidate's live entry key was modified in the current ledger, treat it as an internal consistency failure and do not evict it.
  - Validation: add a regression test where an entry body changes without a TTL change.

- [ ] Re-check genesis-adjacent close-time behavior against current stellar-core.
  - Files: `crates/herder/src/herder.rs`, `crates/herder/src/scp_driver.rs`.
  - Required behavior: align the prefilter and deeper SCP validation paths so the genesis exception is implemented consistently.
  - Validation: add tests for slow-node / genesis-adjacent envelope acceptance and rejection boundaries.

### Priority 3: Interop and catchup behavior gaps

- [ ] Update overlay version advertisement and compatibility logic for the `v38-v39` range.
  - Files: `crates/overlay/src/lib.rs`, `crates/overlay/src/auth.rs`, peer handshake validation.
  - Required behavior: advertise the current range and ensure version compatibility checks match the updated spec.
  - Validation: handshake tests for peers on 37, 38, and 39.

- [ ] Add explicit corrupt-header classification in catchup verification.
  - Files: `crates/history/src/error.rs`, `crates/history/src/verify.rs`, catchup orchestration.
  - Required behavior: distinguish malformed/corrupt downloaded header material from generic local verification failure.
  - Validation: tests for malformed header files and runtime parse failures.

- [ ] Implement replay retry/resume semantics from `current LCL + 1`.
  - Files: `crates/history`, `crates/app/src/app/catchup_impl.rs`.
  - Required behavior: bounded retry for replay/apply failures and restart from current progress rather than original replay start.
  - Validation: inject replay failure mid-range and verify retry resumes from advanced LCL.

### Suggested implementation order

1. `GET_SCP_STATE` limiter
2. pool-share trustline sorting
3. create-contract pairing validation
4. negative `baseFee` rejection
5. tx-set fee-source affordability
6. stale-snapshot live-entry invalidation
7. remaining overlay/close-time/catchup refinements

## Bottom Line

Henyey is already aligned on some of the recent spec changes, especially the per-op fee division-by-zero guard and parts of fee affordability and close-time handling. However, it is **not yet fully adherent** to the recent spec updates overall. The most important divergences are:

- missing `GET_SCP_STATE` rate limiting,
- missing deterministic sorting for pool-share trustline revocation,
- missing create-contract pairing validation,
- and validation behavior that is still weaker than the updated tx-set and catchup specs.
