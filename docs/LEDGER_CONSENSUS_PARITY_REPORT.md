# Consensus Parity Report: `crates/ledger` vs stellar-core v25

**Date:** 2026-02-17
**Scope:** Full pseudocode comparison of `crates/ledger` (Henyey) against `stellar-core/src/ledger/` (stellar-core v25 / protocol 25)
**Method:** Side-by-side pseudocode comparison of all 16 Rust source files against their C++ counterparts

---

## Summary

63 behavioral deltas were identified across the ledger close, state management, and execution pipeline. Of these:

- **5 Critical** — will cause ledger state divergence on real-world traffic
- **9 High** — will cause divergence under specific but plausible conditions
- **12 Medium** — will cause divergence in edge cases or affect result XDR fidelity
- **37 Low** — minor differences unlikely to affect consensus

All file references use the format `file:line` relative to `crates/ledger/src/` (Rust) and `stellar-core/src/ledger/` or `stellar-core/src/` (C++).

---

## Critical Severity

These will cause consensus-breaking divergence on mainnet traffic today.

### L-M1. Genesis header `ledger_seq: 0` instead of 1

- **Rust:** `manager.rs` — genesis ledger header is created with `ledger_seq: 0`
- **C++:** `LedgerManagerImpl.cpp` — uses `GENESIS_LEDGER_SEQ = 1`
- **Impact:** The genesis ledger hash will differ, which propagates to every subsequent header's `previous_ledger_hash`. This breaks consensus from the very first ledger.
- **Fix:** Set `ledger_seq` to 1 in genesis header creation.

### L-M2. Genesis `total_coins: 0` instead of 1,000,000,000,000,000,000

- **Rust:** `manager.rs` — genesis header sets `total_coins: 0`
- **C++:** `LedgerManagerImpl.cpp` — sets `total_coins` to `1_000_000_000_000_000_000` (100 billion XLM in stroops)
- **Impact:** Every header will carry a different `total_coins` value, causing header hash divergence. Also affects inflation calculations and reserve computations that reference total coins.
- **Fix:** Set `total_coins` to `1_000_000_000_000_000_000` in genesis.

### L-H7. `create_next_header` drops upgrades from StellarValue

- **Rust:** `header.rs` — `create_next_header` sets `upgrades` to `VecM::default()` (empty), discarding the upgrades present in the StellarValue
- **C++:** `LedgerHeaderUtils.cpp` — copies the full `StellarValue` including upgrades into the header before applying them
- **Impact:** For any ledger close that includes protocol upgrades, the header hash will differ because the `scpValue` field in the header will have empty upgrades instead of the actual upgrade set. This breaks consensus on every upgrade ledger.
- **Fix:** Copy the full StellarValue (including upgrades) into the header's `scpValue` field, matching C++ behavior.

### L-R1. Soroban state includes CONFIG_SETTING in `is_in_memory_type`

- **Rust:** `soroban_state.rs` — `is_in_memory_type` returns `true` for `CONFIG_SETTING` entries, meaning they are stored in the in-memory Soroban state
- **C++:** `InMemorySorobanState.cpp` — CONFIG_SETTING entries are NOT part of the in-memory Soroban state; they are stored in SQL like other classic entries
- **Impact:** Including CONFIG_SETTING entries in the Soroban state changes the state size calculations, eviction behavior, and rent fee computations. This will cause different fees and different eviction decisions on every ledger with Soroban activity.
- **Fix:** Remove `CONFIG_SETTING` from `is_in_memory_type`.

### L-R2. Protocol version boundary for code size uses wrong comparison

- **Rust:** `soroban_state.rs` — uses `protocol_version < 25` to determine code size limits
- **C++:** `NetworkConfig.cpp` — uses `max(protocol_version, V_23)` as the effective version for code size threshold selection
- **Impact:** For protocols 23-24, the wrong code size limit is applied, causing different rent fee calculations. This affects every Soroban transaction that touches contract code entries.
- **Fix:** Use `max(protocol_version, 23)` as the effective protocol version for code size limit selection.

---

## High Severity

These will cause divergence under specific but realistic conditions.

### L-M3. Module cache eviction missing archived entries

- **Rust:** `manager.rs` — module cache eviction only considers `dead_entries` (deleted entries)
- **C++:** `LedgerManagerImpl.cpp` — evicts BOTH deleted entries AND archived entries from the module cache
- **Impact:** After a ledger that archives contract code, the Rust module cache will retain stale compiled modules. Subsequent Soroban executions may use outdated code, producing different results.
- **Fix:** Include archived entries in module cache eviction.

### L-M4. InMemorySorobanState updated before add_batch

- **Rust:** `manager.rs` — the in-memory Soroban state is updated BEFORE `add_batch` writes entries to the bucket list
- **C++:** `LedgerManagerImpl.cpp` — updates the in-memory Soroban state AFTER `addBatch`
- **Impact:** If `add_batch` fails or modifies the entry set, the in-memory state will be inconsistent with the persisted state. This could cause different Soroban execution results on subsequent ledgers.
- **Fix:** Move Soroban state update to after `add_batch` completes.

### L-M5. No P23 hot archive bug fix for P24 upgrade ledger

- **Rust:** `manager.rs` — no special handling for the protocol 23→24 upgrade boundary
- **C++:** `LedgerManagerImpl.cpp` — applies a specific bug fix at the P24 upgrade boundary to correct hot archive entries corrupted by a P23 bug
- **Impact:** If replaying from genesis or from before the P24 upgrade, the hot archive state will diverge at the upgrade boundary. Not relevant for nodes starting fresh at P24+, but blocks historical replay.
- **Fix:** Implement the P23 hot archive correction at the P24 upgrade boundary, or document as intentional omission for forward-only nodes.

### L-M10. Hot archive restored key filtering removes all restored keys

- **Rust:** `manager.rs` — when filtering restored keys from the hot archive, removes ALL restored key types
- **C++:** `LedgerManagerImpl.cpp` — only filters restored keys of type `CONTRACT_DATA` and `CONTRACT_CODE`
- **Impact:** If non-Soroban entry types are ever restored (unlikely but protocol-valid), they would be incorrectly removed from the hot archive in Rust.
- **Fix:** Only filter `CONTRACT_DATA` and `CONTRACT_CODE` restored keys from the hot archive.

### L-H3. Missing `isValid` header validation

- **Rust:** `header.rs` — no header validation function
- **C++:** `LedgerHeaderUtils.cpp` — `isValid()` validates base fee, max tx set size, base reserve, sequence number, total coins, fee pool, and inflation sequence
- **Impact:** Invalid headers that C++ would reject will be accepted by Rust. This could allow consensus on an invalid ledger state if a malformed header is proposed.
- **Fix:** Implement `is_valid()` header validation matching C++ checks.

### L-D6. No automatic `lastModifiedLedgerSeq` stamping

- **Rust:** `delta.rs` — no automatic stamping of `lastModifiedLedgerSeq` on entries
- **C++:** `LedgerTxn.cpp` — on `seal()`, iterates all modified entries and sets `lastModifiedLedgerSeq` to the current ledger sequence
- **Impact:** If any code path in Rust creates or modifies a ledger entry without explicitly setting `lastModifiedLedgerSeq`, the entry will have a stale or zero value. This affects entry ordering in the bucket list and any logic that reads this field.
- **Fix:** Implement automatic `lastModifiedLedgerSeq` stamping when committing ledger changes, or verify all code paths set it explicitly.

### L-E1. MAX_SEQ_NUM_TO_APPLY not set in parallel execution path

- **Rust:** `execution/mod.rs` — when `deduct_fee=false` (parallel execution), skips setting `MAX_SEQ_NUM_TO_APPLY` temporary entries
- **C++:** `TransactionFrame.cpp` — always creates `MAX_SEQ_NUM_TO_APPLY` entries during fee processing, regardless of execution mode
- **Impact:** Soroban transactions that check `MAX_SEQ_NUM_TO_APPLY` during host function invocation will see different values in the parallel execution path.
- **Fix:** Ensure `MAX_SEQ_NUM_TO_APPLY` entries are created even when fees are not deducted.

### L-R3. Soroban state update has create-if-not-exists fallback

- **Rust:** `soroban_state.rs` — update operation creates the entry if it doesn't exist (silent upsert)
- **C++:** `InMemorySorobanState.cpp` — asserts that the entry exists before updating; aborts if missing
- **Impact:** If a bug causes an update to a non-existent entry, Rust will silently create it (causing state divergence) while C++ would halt the node. This masks bugs and produces wrong state.
- **Fix:** Assert entry existence on update; abort or error if missing.

### L-R4. Soroban state delete doesn't assert entry existence

- **Rust:** `soroban_state.rs` — delete is a no-op if the entry doesn't exist
- **C++:** `InMemorySorobanState.cpp` — asserts that the entry exists before deleting; aborts if missing
- **Impact:** Same as L-R3 — silently ignoring deletion of non-existent entries masks bugs and can lead to state divergence.
- **Fix:** Assert entry existence on delete; abort or error if missing.

---

## Medium Severity

These cause divergence in edge cases or affect result XDR fidelity.

### L-M6. LedgerCloseMeta always V2

- **Rust:** `manager.rs` — always produces `LedgerCloseMeta::V2` regardless of protocol version
- **C++:** `LedgerCloseMetaFrame.cpp` — selects `V0`, `V1`, or `V2` depending on the protocol version
- **Impact:** Downstream consumers (e.g., Horizon, RPC) that rely on specific meta versions may break. While meta is not consensus-critical, it affects interoperability.
- **Fix:** Select meta version based on protocol: V0 for <20, V1 for 20, V2 for >=21.

### L-M7. MAX_SEQ_NUM_TO_APPLY entries not created during fee processing

- **Rust:** `manager.rs` — fee processing path does not create `MAX_SEQ_NUM_TO_APPLY` temporary ledger entries
- **C++:** `LedgerManagerImpl.cpp` — creates these entries as part of fee processing for each transaction
- **Impact:** Soroban host functions that read `MAX_SEQ_NUM_TO_APPLY` will get different values, potentially causing transaction acceptance/rejection differences.
- **Fix:** Create `MAX_SEQ_NUM_TO_APPLY` entries during fee processing.

### L-M9. Fees processed via bulk delta vs per-tx LedgerTxn commits

- **Rust:** `manager.rs` — processes all fees in a single bulk delta operation
- **C++:** `LedgerManagerImpl.cpp` — processes fees per-transaction with individual `LedgerTxn` commits between each
- **Impact:** If fee processing for one transaction affects the state seen by the next (e.g., an account paying fees for multiple transactions), the bulk approach may produce different intermediate states.
- **Fix:** Process fees per-transaction with intermediate commits, or verify that bulk processing produces identical final state.

### L-M11. Module cache only compiles for current protocol version

- **Rust:** `manager.rs` — module cache compilation uses only the current protocol version
- **C++:** `LedgerManagerImpl.cpp` — may compile modules for both current and next protocol versions during upgrade boundaries
- **Impact:** At protocol upgrade boundaries, the module cache may be missing compiled modules for the new protocol version, causing compilation during execution and potentially different behavior.
- **Fix:** Handle protocol upgrade boundaries by compiling modules for both versions when appropriate.

### L-M13. No invariant checks (InvariantManager)

- **Rust:** `manager.rs` — no invariant checking after ledger close
- **C++:** `LedgerManagerImpl.cpp` — calls `InvariantManager::checkOnLedgerClose()` to verify conservation of lumens, account balance invariants, etc.
- **Impact:** Invariant violations that C++ would detect (and potentially halt on) will go undetected in Rust. While invariants don't affect consensus directly, they catch bugs that would.
- **Fix:** Implement key invariant checks, at minimum conservation of lumens and bucket list consistency.

### L-M14. Upgrades applied to delta vs child LedgerTxn per-upgrade

- **Rust:** `manager.rs` — all upgrades are applied to a single delta
- **C++:** `LedgerManagerImpl.cpp` — creates a new child `LedgerTxn` for each upgrade, committing between upgrades
- **Impact:** If one upgrade affects the state read by a subsequent upgrade (e.g., upgrading base reserve then upgrading max tx set size), the single-delta approach may produce different results.
- **Fix:** Apply each upgrade in its own transaction scope with intermediate commits.

### L-M15. Eviction ordering relative to add_batch

- **Rust:** `manager.rs` — eviction may occur at a different point relative to `add_batch` compared to C++
- **C++:** `LedgerManagerImpl.cpp` — eviction has a specific ordering relative to batch addition
- **Impact:** Different eviction ordering could cause different entries to be evicted, affecting the bucket list hash.
- **Fix:** Verify and align eviction ordering with C++.

### L-H5. Header `ext` forced to V0

- **Rust:** `header.rs` — header extension is always set to `V0`, discarding any V1 flags from the previous header
- **C++:** `LedgerHeaderUtils.cpp` — preserves the header extension version and flags
- **Impact:** If the network ever uses V1 header extensions (for flags like `SOROBAN_ENABLED`), Rust will discard them, producing different header hashes.
- **Fix:** Preserve header extension from the previous header and update flags as needed.

### L-H9. Skip list verification uses wrong model

- **Rust:** `header.rs` — skip list verification logic differs from C++ (uses header hashes vs bucket list hashes, or wrong skip distances)
- **C++:** `LedgerHeaderUtils.cpp` — skip list entries reference specific previous ledger headers at powers-of-two distances
- **Impact:** Skip list validation will produce wrong results, though skip lists are primarily used for catchup/history and not directly in consensus.
- **Fix:** Align skip list computation with C++ algorithm.

### L-R5. OfferDescriptor Eq/Ord trait inconsistency

- **Rust:** `offer.rs` — `Eq` and `Ord` trait implementations for `OfferDescriptor` may have inconsistencies (e.g., `Eq` derived but `Ord` manually implemented)
- **C++:** `LedgerTxnOfferSQL.cpp` — consistent comparison using `isBetterOffer`
- **Impact:** Offer ordering in the order book could differ, causing different crossing behavior in DEX operations.
- **Fix:** Verify that `Eq`, `PartialOrd`, and `Ord` implementations are consistent and match C++'s `isBetterOffer` semantics.

### L-R6. Config upgrade constant differences

- **Rust:** `config_upgrade.rs` — some configuration constants or boundaries may differ from C++
- **C++:** `NetworkConfig.cpp` — uses specific constants for Soroban configuration limits
- **Impact:** Configuration upgrades that hit boundary conditions may be accepted/rejected differently.
- **Fix:** Audit all configuration constants against C++ values.

### L-R7. Cost parameter validation differences

- **Rust:** `config_upgrade.rs` — cost parameter validation may not match C++ exactly
- **C++:** `NetworkConfig.cpp` — validates cost model parameters during configuration upgrades
- **Impact:** Invalid cost parameters that C++ rejects could be accepted by Rust, causing different Soroban fee calculations.
- **Fix:** Align cost parameter validation with C++.

### L-R9. Trustline IssuerImpl sentinel values

- **Rust:** `lib.rs` (trustlines module) — sentinel/placeholder issuer values may differ
- **C++:** `TrustLineWrapper.cpp` — uses specific sentinel values for issuer fields
- **Impact:** Trustline lookups or comparisons involving sentinel issuers may produce different results.
- **Fix:** Verify sentinel values match C++ exactly.

---

## Low Severity

These are unlikely to affect consensus but represent correctness gaps.

### L-H1, L-H2, L-H4, L-H8, L-H10. Minor header structural differences

- Various minor structural differences in header handling: field ordering, default values for non-consensus fields, and initialization patterns.
- **Impact:** No consensus impact; architectural differences only.

### L-D1. Permissive coalescing of ledger entry changes

- **Rust:** `delta.rs` — coalescing of multiple modifications to the same entry is more permissive than C++
- **Impact:** Could mask bugs but unlikely to produce different final state if each individual operation is correct.

### L-D2. Previous-state retrieval differences

- **Rust:** `delta.rs` — previous state retrieval may return different intermediate states than C++
- **Impact:** Affects rollback behavior; unlikely to surface if transactions succeed.

### L-D7, L-D8. Sponsorship tracking location

- **Rust:** `delta.rs` — sponsorship tracking is handled at a different layer than C++
- **Impact:** If sponsorship tracking is correct at the operation level, the layer difference is non-impacting.

### L-D3, L-D4, L-D5, L-D9, L-D10. Architectural delta differences

- Various architectural differences in the delta/transaction model: nesting depth, commit semantics, rollback granularity.
- **Impact:** These are design decisions that don't affect observable behavior if the operations produce correct results.

### L-S1, L-S2, L-S3, L-S5, L-S6, L-S7, L-S8, L-S10. Snapshot architectural differences

- Various snapshot implementation differences: pre-v8 code paths (irrelevant for P24+), caching strategies, lock granularity, iterator patterns.
- **Impact:** No consensus impact; performance and architecture differences only.

### L-S4. No CompleteConstLedgerState atomicity

- **Rust:** `snapshot.rs` — no equivalent of C++'s `CompleteConstLedgerState` for atomic multi-bucket reads
- **Impact:** Could cause torn reads during concurrent access, but unlikely to affect consensus if ledger close is single-threaded.

### L-S9. Pool share trustline query surface

- **Rust:** `snapshot.rs` — pool share trustline query API differs from C++
- **Impact:** If queries return correct results, the API surface difference is non-impacting.

### L-E2–L-E8. Execution architectural differences

- **L-E2:** Sub-SHA256 type is cosmetic (doesn't affect hash)
- **L-E3:** Meta ext V1 is config-dependent (matches C++ when configured correctly)
- **L-E4–L-E8:** Signature verification, result mapping, and tx set handling verified correct
- **Impact:** No consensus impact.

### L-M8. Two-thread vs single-thread apply model

- **Rust:** `manager.rs` — uses a different threading model for transaction application
- **C++:** `LedgerManagerImpl.cpp` — uses a specific two-thread model
- **Impact:** Threading model doesn't affect deterministic output if synchronization is correct.

### L-M12. No module cache rebuild heuristic

- **Rust:** `manager.rs` — no heuristic for when to rebuild the Wasm module cache
- **C++:** `LedgerManagerImpl.cpp` — periodically rebuilds the module cache based on usage patterns
- **Impact:** Performance difference only; no consensus impact.

### L-R8. Pre-V9 overflow in fee calculations

- **Rust:** `lib.rs` — potential overflow in fee calculations for pre-V9 protocols
- **Impact:** Irrelevant for P24+ only operation.

### L-R10. Fee calculation semantics

- **Rust:** `lib.rs` — minor semantic differences in fee computation
- **Impact:** Needs verification but unlikely to diverge for valid inputs.

---

## Structural Differences (Non-Consensus)

These are architectural differences that do not affect observable behavior:

| Aspect | Rust (Henyey) | C++ (stellar-core) |
|--------|---------------|---------------------|
| State model | `Delta` with explicit coalescing | Nested `LedgerTxn` with RAII commit/rollback |
| Snapshot | `LedgerSnapshot` with bucket list reads | `LedgerStateSnapshot` with SQL + bucket list |
| Threading | Async/parallel execution model | Two-thread apply model |
| Module cache | Simple map with eviction | `ModuleCache` with rebuild heuristics |
| Invariants | Not implemented | `InvariantManager` with pluggable checks |
| Meta output | Always V2 | Version-dependent (V0/V1/V2) |

---

## Scope Gaps (Missing Features)

Features present in C++ but entirely absent in Rust, beyond the behavioral deltas above:

1. **Invariant checking** — No conservation-of-lumens or other invariant checks after ledger close (covered in L-M13)
2. **Header validation** — No `isValid()` check on incoming headers (covered in L-H3)
3. **P23 hot archive bug fix** — No protocol upgrade boundary correction (covered in L-M5)
4. **Module cache rebuild heuristic** — No periodic cache rebuild (covered in L-M12)

---

## Recommended Fix Priority

1. **Immediate (blocks any parity):** L-M1, L-M2, L-H7, L-R1, L-R2
2. **High priority (blocks correctness):** L-M3, L-M4, L-M5, L-M10, L-H3, L-D6, L-E1, L-R3, L-R4
3. **Medium priority (edge cases):** L-M6, L-M7, L-M9, L-M11, L-M13, L-M14, L-M15, L-H5, L-H9, L-R5, L-R6, L-R7, L-R9
4. **Low priority (hardening):** All LOW items

---

## Methodology

Each Rust source file in `crates/ledger/src/` was compared against its C++ counterpart(s) in `stellar-core/src/ledger/` using side-by-side pseudocode generation. The comparison focused on:

- Guard check ordering and conditions
- State mutations and their sequencing
- Decision points and branching logic
- Cross-function calls and their parameters
- Return values and error codes
- Genesis initialization values
- Protocol version boundary handling

Excluded from comparison: test code, logging, metrics, memory management, and type conversions (unless containing logic).
