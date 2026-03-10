# TX Crate Simplification Tracking

## Status Legend
- [ ] Not started
- [~] In progress
- [x] Completed
- [-] Skipped (with reason)

---

## 1. LARGE MODULE / DUPLICATION — `state/mod.rs`: Generic `EntryStore<K, V>`
- **Location**: `crates/tx/src/state/mod.rs`, `crates/tx/src/state/entry_store.rs`, `crates/tx/src/state/entries.rs`
- **Task**: Introduce a generic `EntryStore<K, V>` to replace per-type bookkeeping pattern
- **Scope**: Converted 5 clean types (ClaimableBalance, LiquidityPool, ContractCode, ContractData, Data); 4 complex types (Account, Trustline, Offer, TTL) stay hand-written
- [x] Design and implement `EntryStore<K, V>` with 44 unit tests
- [x] Convert ClaimableBalance, LiquidityPool, ContractCode, ContractData, Data
- [x] Verify with clippy + tests (888 tx + 52 ledger tests pass, 0 clippy warnings)

## 2. DUPLICATION — DEX helpers duplicated across 3 files
- **Location**: `manage_offer.rs`, `path_payment.rs`, `trust_flags.rs`
- **Task**: Extract shared offer helpers to `operations/execute/offer_utils.rs`
- **Estimated savings**: ~400 lines → **~290 lines eliminated**
- [x] Create `offer_utils.rs` with `offer_liabilities_sell`, `can_sell_at_most`, `cross_offer_v10`, `delete_offer_with_sponsorship`
- [x] Update `manage_offer.rs` — removed local `offer_liabilities_sell`, `can_sell_at_most`, `cross_offer_v10`; replaced inline delete+sponsorship with `delete_offer_with_sponsorship`
- [x] Update `path_payment.rs` — removed local `offer_liabilities_sell`, `can_sell_at_most`, `cross_offer_v10` (~175 lines)
- [x] Update `trust_flags.rs` — replaced local `offer_liabilities` with shared `offer_liabilities_sell`; kept `release_offer_liabilities` (uses `saturating_sub` for best-effort deauth cleanup)
- [x] Verify with clippy + tests

## 3. GOD FUNCTION — `execute_manage_offer` (416 lines)
- **Location**: `operations/execute/manage_offer.rs:52-467`
- **Task**: Split into `validate_offer_params()`, `execute_exchange()`, `finalize_offer()`
- [-] Skipped: The function's phases share ~15 local variables (`old_offer`, `sponsor`, `reserve_subentry`, `selling_liab`, `offer_flags`, `passive`, `sheep_sent`, `wheat_received`, etc.) that would all need to be passed to sub-functions, recreating the too-many-arguments problem. The function is already well-structured with clear phase comments and early returns. Extracting `cross_offer_v10` and `delete_offer_with_sponsorship` (Item 2) already removed the main duplication. Further splitting would add complexity rather than reduce it.
- [x] Verify with clippy + tests

## 4. GOD FUNCTION — `execute_operation_with_soroban` (333 lines, 12 params)
- **Location**: `operations/execute/mod.rs:796-1128`
- **Task**: Extract Soroban TTL/restore blocks; introduce `SorobanOperationContext` struct
- [-] Skipped: Extract `execute_extend_footprint_ttl_inline()` and `execute_restore_footprint_inline()` — these blocks are tightly coupled to local variables (snapshots, hot_archive_restores, rent_changes) that would need to flow in and out, making extraction add complexity rather than reduce it
- [x] Introduce `SorobanContext` struct bundling 5 optional Soroban params (soroban_data, config, module_cache, hot_archive, ttl_key_cache)
- [x] Introduce `TxIdentity` struct bundling tx_source_id, tx_seq, op_index — reduces `execute_operation_with_soroban` from 12 to 6 params
- [x] Verify with clippy + tests

## 5. DUPLICATION — P24/P25 parallel code in `soroban/host.rs`
- **Location**: `soroban/host.rs`
- **Task**: Extract shared helpers; macro-ify duplicated structs/functions
- [x] Extract `derive_fallback_prng_seed()`
- [x] Extract `extract_restored_indices()`
- [x] Macro-ify `extract_rent_changes_from_typed` (P24/P25)
- [x] Macro-ify `WasmCompilationContext` (P24/P25) via `define_wasm_compilation_context!`
- [x] Verify with clippy + tests

## 6. GOD FUNCTION — `apply_soroban_storage_change` (258 lines)
- **Location**: `operations/execute/invoke_host_function.rs:699-956`
- **Task**: Extract `apply_contract_entry_change()` and `create_or_update_ttl()`
- [x] Extract `should_create_contract_entry()` — unifies ContractData/Code hot-archive restore logic
- [x] Extract `create_or_update_ttl()` — eliminates 3× repeated if/else TTL pattern
- [x] Verify with clippy + tests

## 7. DUPLICATION — `live_execution.rs` regular/fee-bump pairs
- **Location**: `crates/tx/src/live_execution.rs`
- **Task**: Unify 4 pairs of near-identical functions
- [x] Remove `process_fee_seq_num_fee_bump` (dead code — zero callers in production or tests; ledger crate computes fee-bump fees inline)
- [x] Remove `process_post_apply_fee_bump` (dead code — zero callers)
- [x] Remove `process_post_tx_set_apply_fee_bump` (dead code — zero callers)
- [x] Verify with clippy + tests

## 8. DUPLICATION — `path_payment.rs` strict_receive / strict_send
- **Location**: `operations/execute/path_payment.rs:35-320`
- **Task**: Parameterize with `PathDirection` enum
- [-] Skipped: The two functions traverse the path in opposite directions (backward vs forward), update balances in opposite order (dest-first vs source-first), and accumulate offer trails differently (prepend vs append). These structural differences are load-bearing protocol semantics, not superficial duplication. The shared helpers (`update_source_balance`, `update_dest_balance`, `convert_with_offers_and_pools`) already capture the correct level of reuse. Unifying would obscure protocol-critical ordering invariants for ~60-80 lines of savings.

## 9. GOD FUNCTION — `execute_liquidity_pool_deposit` (266 lines) with A/B duplication
- **Location**: `operations/execute/liquidity_pool.rs:26-291`
- **Task**: Extract helpers to collapse duplicated A/B asset blocks
- [x] Extract `resolve_deposit_asset()` — combines trustline lookup, auth check, and available balance (Pairs 1-3, ~56 → ~10 lines)
- [x] Extract `debit_asset()` — deducts asset from source (Pair 4, ~39 → ~6 lines)
- [x] Collapse `can_credit_asset` pair in withdraw into loop (Pair 5, ~27 → ~10 lines)
- [x] Verify with clippy + tests

## 10. GOD FUNCTION — `execute_change_trust` (210 lines)
- **Location**: `operations/execute/change_trust.rs:21-230`
- **Task**: Split into `delete_trustline()`, `update_trustline()`, `create_trustline()`
- [-] Skipped: the three branches (delete ~50 lines, update ~20 lines, create ~90 lines) are each reasonable length and share 5-6 local variables, so extraction would mostly shuffle complexity rather than reduce it
- [x] Verify with clippy + tests

## 11. DUPLICATION — `frame.rs` envelope matching repeated 16×
- **Location**: `crates/tx/src/frame.rs`
- **Task**: Add `inner_tx()` and `inner_envelope()` accessors
- [x] Add private `inner_tx()` → `Option<&Transaction>` helper
- [x] Add private `inner_envelope()` → `Option<&TransactionV1Envelope>` helper
- [x] Refactor 9 methods to use helpers: `inner_source_account`, `sequence_number`, `inner_fee`, `operations`, `memo`, `preconditions`, `soroban_data`, `inner_signatures`, `inner_tx_size_bytes`
- [-] 6 Group B methods (source_account, fee_source_account, fee, total_fee, signatures, signature_payload) access outer/fee-bump-specific fields — cannot be unified
- [x] Verify with clippy + tests

## 12. DEAD CODE — `InvokeHostFunctionOutput`, `EncodedContractEvent`, `compute_rent_fee_for_new_entry`
- **Location**: `soroban/protocol/types.rs`, `soroban/host.rs`
- **Task**: Remove dead types and functions
- [x] Remove `InvokeHostFunctionOutput` and `EncodedContractEvent`
- [x] Remove `compute_rent_fee_for_new_entry` and its re-export
- [x] Verify with clippy + tests

## 13. CLIPPY SUPPRESSIONS — 11× `clippy::too_many_arguments` → 8×
- **Location**: Various files
- **Task**: Introduce context structs to eliminate suppressions
- [x] Introduce `SorobanContext` struct in `soroban/mod.rs` — eliminates suppression on `execute_operation_with_soroban` and `execute_invoke_host_function`
- [x] Introduce `TxIdentity` struct in `operations/execute/mod.rs` — eliminates suppression on `redeem_into_claimable_balance` in trust_flags.rs
- [-] Remaining 8 suppressions cannot be reasonably eliminated:
  - 3× `soroban/host.rs` — protocol-specific dispatch functions with p24/p25 cache types
  - 1× `invoke_host_function.rs` — private `execute_contract_invocation` (9 params after unwrap)
  - 1× `restore_footprint.rs` — concrete params after option unwrap
  - 1× `liquidity_pool.rs` — pure math with 10 scalar params
  - 1× `path_payment.rs` — pure math with 8 scalar params
  - 1× `manage_offer.rs` — 9 natural operation params
- [x] Verify with clippy + tests

## 14. DUPLICATION — `result.rs` error-code-to-result mapping 3×
- **Location**: `crates/tx/src/result.rs`
- **Task**: Extract `code_to_result()` helper
- [x] Unify `create_error` and `set_error` via shared `code_to_result()` function
- [-] `to_xdr_result` maps from `TxResultCode` (internal enum), not `TransactionResultCode` (XDR) — different types, cannot share
- [x] Verify with clippy + tests

## 15. OVERLY BROAD VISIBILITY — 11 `pub` types used only within `soroban/`
- **Location**: Various `soroban/` files
- **Task**: Narrow to `pub(crate)` or `pub(super)`
- [x] Narrowed `LedgerSnapshotAdapter` and `LedgerSnapshotAdapterP25` to private
- [-] Skipped 9 other types: they are re-exported as `pub` from private modules to keep them usable from tests. Removing re-exports triggers dead_code errors under `-D warnings`. These types are effectively dead code candidates but removing them is a larger scope change.
- [x] Verify with clippy + tests

## 16. GOD FUNCTION — `rollback_to_savepoint` (230 lines) with deep nesting
- **Location**: `state/mod.rs:1373-1602`
- **Task**: Refactor Phase 6 metadata rollback blocks
- [x] Extract `rollback_routed_metadata()` — generic helper for HashMap-based metadata (last_modified, sponsorships)
- [x] Extract `rollback_routed_set_metadata()` — variant for HashSet-based metadata (sponsorship_ext)
- [x] Collapsed ~120 lines of Phase 6 into 3 helper calls
- [x] Verify with clippy + tests

## 17. DUPLICATION — `events.rs` / `meta_builder.rs` shared helpers
- **Location**: `events.rs:838-844`, `meta_builder.rs:846-852`
- **Task**: Extract `make_symbol_scval` / `make_string_scval` to shared module
- [x] Create shared `scval_utils.rs` and update both files
- [x] Verify with clippy + tests

## 18. MISSING MODULE DOC — 4 files over 100 lines with no `//!` doc
- **Location**: `soroban/error.rs`, `state/offer_index.rs`, `state/sponsorship.rs`, `state/ttl.rs`
- **Task**: Add `//!` module doc
- [x] Add doc comments to all 4 files
- [x] Verify with clippy + tests

## 19. DEAD CODE — `LedgerSnapshotAdapter::new` (`#[allow(dead_code)]`)
- **Location**: `soroban/host.rs:283-291`
- **Task**: Remove or gate with `#[cfg(test)]`
- [x] Remove the method
- [x] Verify with clippy + tests

## 20. DUPLICATION — `change_trust.rs` increment/decrement pool use count
- **Location**: `operations/execute/change_trust.rs:348-396`
- **Task**: Unify with direction parameter
- [x] Create `adjust_pool_use_count(state, source, asset, delta: i32)`
- [x] Verify with clippy + tests
