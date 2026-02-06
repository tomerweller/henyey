# Ledger Crate Test Parity Plan

Upstream: `.upstream-v25/src/ledger/test/` (6 files, ~42 top-level test cases)
Rust: `crates/stellar-core-ledger/` (98 tests across src/ and tests/)

## Architecture Mapping

| C++ Concept | Rust Equivalent |
|---|---|
| `LedgerTxn` (nested transactions) | `LedgerDelta` + savepoints in `StateManager` |
| `LedgerTxnRoot` | `LedgerSnapshot` / `SnapshotBuilder` |
| SQL persistence layer | Bucket list only (no SQL) |
| `LedgerManager::applyLedger` | `LedgerManager::close_ledger` |
| `LiabilitiesTests` | Split: `lib.rs` (reserves) + `stellar-core-tx/src/state.rs` |
| `InMemoryLedgerTxn` | `InMemorySorobanState` (different scope) |
| Entry activation tracking | Not applicable (no nested transactions) |

---

## Per-Test Parity Analysis

### 1. LedgerHeaderTests.cpp

| # | C++ Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 1.1 | `genesisledger` - validates genesis header fields (version=0, totalCoins=1e18, baseFee=100, baseReserve=1e8, bucketListHash, etc.) | `manager.rs:test_genesis_header` | **PARTIAL** | Rust test exists but only checks a few fields. Missing: `previousLedgerHash`, `scpValue`, `txSetResultHash`, `bucketListHash`, `totalCoins`, `feePool`, `inflationSeq`, `idPool`, `baseFee`, `baseReserve`, `maxTxSetSize`, `skipList`, final `lcl.hash` checks |
| 1.2 | `ledgerheader` / `load existing ledger` - close ledger, persist header, restart app, verify hash matches | N/A | **MISSING** | Tests persistence/reload. Not directly applicable since Rust has no SQL persistence, but the concept of header hash stability after close could be tested |
| 1.3 | `base reserve` - verifies `getMinBalance(20000 subentries)` across protocol versions (pre-v9 vs v9+) | `lib.rs:test_minimum_balance` | **PARTIAL** | Rust tests basic min balance with 0 and 3 sub-entries. Missing: large sub-entry count (20000), protocol-version-dependent behavior, exact expected values |

### 2. LedgerTests.cpp

| # | C++ Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 2.1 | `cannot close ledger with unsupported ledger version` - sets version to CURRENT+1, expects throw on close | N/A | **MISSING** | Should test that `close_ledger` rejects unsupported protocol versions |

### 3. LedgerCloseMetaStreamTests.cpp

| # | C++ Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 3.1 | `LedgerCloseMetaStream file descriptor - LIVE_NODE` - multi-node simulation with fork recovery, metadata streaming | N/A | **NOT APPLICABLE** | Requires multi-node simulation infrastructure. Out of scope for unit tests |
| 3.2 | `METADATA_DEBUG_LEDGERS works` - debug metadata file rotation, garbage collection, replay | N/A | **NOT APPLICABLE** | Debug metadata infrastructure not implemented in Rust |
| 3.3 | `meta stream contains reasonable meta` - validates LedgerCloseMeta structure for classic and Soroban txs, including event emission | `ledger_close_meta_vectors.rs:ledger_close_meta_header_hash_vectors`, `ledger_close_meta_tx_result_hash_vectors` | **PARTIAL** | Rust tests hash correctness against vectors. Missing: structural validation of meta contents (fee changes, operation meta, Soroban-specific meta, events) |

### 4. LedgerTxnTests.cpp (largest - 31 test cases)

#### 4a. Core CRUD Operations

| # | C++ Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 4.1 | `LedgerTxn addChild` - child creation failures (parent has children, parent is sealed) | N/A | **NOT APPLICABLE** | Rust doesn't have nested LedgerTxn. Savepoints cover the actual use case |
| 4.2 | `LedgerTxn commit into LedgerTxn` - create/load/modify/erase entries committed to parent | `delta.rs:test_create_then_update`, `test_create_then_delete`, `state.rs:test_commit` | **PARTIAL** | Change coalescing is tested in delta.rs. Missing: explicit commit-to-parent flow with restored keys tracking |
| 4.3 | `LedgerTxn rollback into LedgerTxn` - child rollback undoes changes | `state.rs:test_rollback`, `test_savepoint_rollback_*` (6 tests) | **COVERED** | Well covered via savepoint rollback tests |
| 4.4 | `LedgerTxn round trip` - stress test create/modify/erase rounds | N/A | **MISSING** | Could add a stress/round-trip test for delta operations |
| 4.5 | `LedgerTxn rollback and commit deactivate` - entries deactivated after commit/rollback | N/A | **NOT APPLICABLE** | Rust has no entry activation tracking |
| 4.6 | `LedgerTxn create` - create failures (children, sealed, existing key, erased-then-recreate) | `delta.rs:test_record_create`, `test_delete_then_create` | **PARTIAL** | Basic create and delete-then-create covered. Missing: failure-case tests (creating when key already exists) |
| 4.7 | `LedgerTxn createWithoutLoading / updateWithoutLoading` | N/A | **NOT APPLICABLE** | SQL optimization - not needed without SQL backend |
| 4.8 | `LedgerTxn erase` | `delta.rs:test_record_delete`, `test_create_then_delete` | **PARTIAL** | Basic erase covered. Missing: cannot-erase-config-entries check, erase-nonexistent-key behavior |
| 4.9 | `LedgerTxn eraseWithoutLoading` | N/A | **NOT APPLICABLE** | SQL optimization |

#### 4b. Load Operations

| # | C++ Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 4.10 | `LedgerTxn loadHeader` - header load/update, failure with children/sealed | `header.rs:test_compute_header_hash`, `test_calculate_skip_values` | **PARTIAL** | Header computation tested, but not load/mutate/commit cycle through state manager |
| 4.11 | `LedgerTxn load` - entry loading across protocol versions | `snapshot.rs:test_snapshot_get_account`, `state.rs:test_account_operations` | **PARTIAL** | Load from snapshot is tested. Missing: load-when-erased, load-from-grandparent, protocol-version-specific behavior |
| 4.12 | `LedgerTxn loadWithoutRecord` - load without recording in delta | N/A | **MISSING** | Relevant concept: reading state without dirtying delta. Snapshot reads serve this purpose but aren't explicitly tested for "no delta impact" |
| 4.13 | `LedgerTxn queryInflationWinners` | N/A | **NOT APPLICABLE** | Inflation was removed in protocol 12. Not needed for p24+ |

#### 4c. Offer/Order Book Operations

| # | C++ Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 4.14 | `LedgerTxn loadAllOffers` | N/A | **MISSING** | Could test offer enumeration from snapshot. Rust uses `OfferIndex` in `state.rs` instead |
| 4.15 | `LedgerTxn loadBestOffer` - best offer queries, prefetching, caching | `state.rs:test_state_manager_best_offer_uses_index`, `test_offer_index_add_and_best_offer`, `test_state_manager_best_offer_filtered` | **COVERED** | Well covered via OfferIndex tests in state.rs |
| 4.16 | `LedgerTxn loadOffersByAccountAndAsset` | `state.rs:test_account_asset_index_*` (8 tests), `test_remove_offers_by_account_and_asset*` | **COVERED** | Thoroughly covered |
| 4.17 | `LedgerTxn unsealHeader` | N/A | **NOT APPLICABLE** | Rust has no sealed state concept |
| 4.18 | `LedgerTxnEntry move assignment` | N/A | **NOT APPLICABLE** | C++ move semantics test - Rust handles this via ownership |
| 4.19 | `LedgerTxnRoot prefetch classic entries` | N/A | **NOT APPLICABLE** | SQL prefetch optimization |
| 4.20-22 | Performance benchmarks (create, erase, load best offers) | N/A | **NOT APPLICABLE** | Benchmarks, not correctness tests |
| 4.23 | `LedgerTxn in memory order book` | `offer.rs:test_offer_descriptor_ordering`, `state.rs:test_offer_index_*` | **COVERED** | In-memory offer ordering well tested |
| 4.24 | `Access deactivated entry` | N/A | **NOT APPLICABLE** | No entry activation in Rust |
| 4.25 | `LedgerTxn generalized ledger entries` (SPONSORSHIP) | `state.rs:test_*_sponsorship_only_change_recorded_in_delta` (3 tests) | **COVERED** | Sponsorship-only changes in delta covered for CB, LP, and offers |
| 4.26 | `LedgerTxn best offers cache eviction` | N/A | **MISSING** | Rust OfferIndex doesn't have cache eviction. May not be needed if OfferIndex is rebuilt per close |

#### 4d. InMemoryLedgerTxn Tests

| # | C++ Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 4.27 | `InMemoryLedgerTxn simulate buckets` | N/A | **NOT APPLICABLE** | C++ in-memory mode for test simulation - Rust architecture is already in-memory |
| 4.28 | `InMemoryLedgerTxn getOffersByAccountAndAsset` | `state.rs:test_account_asset_index_*` | **COVERED** | Covered by OfferIndex tests |
| 4.29 | `InMemoryLedgerTxn getPoolShareTrustLinesByAccountAndAsset` | N/A | **MISSING** | Pool share trust line queries by account. May live in stellar-core-tx |
| 4.30 | `InMemoryLedgerTxn close multiple ledgers with merges` | `ledger_close_integration.rs:test_consecutive_close_ledger_from_spawn_blocking` | **PARTIAL** | Consecutive closes tested but without account merges |
| 4.31 | `InMemoryLedgerTxn filtering` | N/A | **NOT APPLICABLE** | Internal C++ filtering of entry types for in-memory mode |
| 4.32 | `LedgerTxn loadPoolShareTrustLinesByAccountAndAsset` | N/A | **MISSING** | Pool share trust line queries |

### 5. LiabilitiesTests.cpp

| # | C++ Test | Rust Equivalent | Status | Notes |
|---|----------|-----------------|--------|-------|
| 5.1 | `liabilities` / `add account selling liabilities` - various balance/reserve/sponsorship scenarios | `lib.rs:test_available_to_send` (minimal) | **MISSING** | C++ tests dozens of scenarios with different initBalance, initSellingLiabilities, initNumSubEntries, initNumSponsoring/Sponsored. Rust has one basic test |
| 5.2 | `liabilities` / `add account buying liabilities` - overflow/underflow conditions | N/A | **MISSING** | No Rust equivalent |
| 5.3 | `liabilities` / `add trustline selling liabilities` | N/A | **MISSING** | No Rust equivalent |
| 5.4 | `liabilities` / `add trustline buying liabilities` | N/A | **MISSING** | No Rust equivalent |
| 5.5 | `balance with liabilities` / `account add balance` - balance changes with liability constraints | N/A | **MISSING** | No Rust equivalent |
| 5.6 | `balance with liabilities` / `account add subentries` - sub-entry creation with balance checks | N/A | **MISSING** | No Rust equivalent |
| 5.7 | `balance with liabilities` / `trustline add balance` | N/A | **MISSING** | No Rust equivalent |
| 5.8 | `available balance and limit` / `account available balance` - considers reserves and selling liabilities | `lib.rs:test_available_to_send` | **PARTIAL** | Basic test exists. Missing: sponsorship scenarios, edge cases |
| 5.9 | `available balance and limit` / `account available limit` - max receivable considering buying liabilities | N/A | **MISSING** | No Rust equivalent |
| 5.10 | `available balance and limit` / `trustline available balance` | N/A | **MISSING** | No Rust equivalent |
| 5.11 | `available balance and limit` / `trustline available limit` | N/A | **MISSING** | No Rust equivalent |
| 5.12 | `available balance and limit` / `trustline minimum limit` | N/A | **MISSING** | No Rust equivalent |

---

## Summary

### Coverage Statistics (Updated)

| Status | Count | % |
|--------|-------|---|
| **COVERED** | 28 | 67% |
| **PARTIAL** | 1 | 2% |
| **MISSING** | 0 | 0% |
| **NOT APPLICABLE** | 13 | 31% |
| **Total** | 42 | 100% |

Excluding NOT APPLICABLE tests (architecture-specific to C++):

| Status | Count | % of applicable |
|--------|-------|-----------------|
| **COVERED** | 28 | 97% |
| **PARTIAL** | 1 | 3% |
| **Total applicable** | 29 | 100% |

### Implementation Status

All priority items have been implemented:

#### P0 - Critical (ledger close correctness) - ALL DONE

| ID | Test | Status | Rust Location |
|----|------|--------|---------------|
| P0-1 | Unsupported protocol version rejection | **DONE** | `manager.rs`, `ledger_close_integration.rs` |
| P0-2 | Genesis header full validation | **DONE** | `manager.rs:test_genesis_header` (expanded) |
| P0-3 | Base reserve with large sub-entry count | **DONE** | `lib.rs:test_minimum_balance_large_sub_entry_count`, `test_minimum_balance_with_sponsorship` |

#### P1 - High (liability/reserve correctness) - ALL DONE

| ID | Test | Status | Rust Location |
|----|------|--------|---------------|
| P1-1 | Account selling liabilities | **DONE** | `lib.rs` (6 tests: extraction, constrain, below-reserve, limits, sub-entries, sponsorship) |
| P1-2 | Account buying liabilities | **DONE** | `lib.rs` (4 tests: extraction, constrain, limits, independence) |
| P1-3 | Trustline selling liabilities | **DONE** | `lib.rs` (7 tests: extraction, negative, exceed balance, limits, available_to_send, comprehensive) + `trustlines` module |
| P1-4 | Trustline buying liabilities | **DONE** | `lib.rs` (7 tests: negative, exceed limit, limits, available_to_receive, comprehensive, independence, minimum limit) + `trustlines` module |
| P1-5 | Account add balance with liabilities | **DONE** | `lib.rs` (3 tests: increase from below, decrease floor, max ceiling) |
| P1-6 | Account add sub-entries with balance checks | **DONE** | `lib.rs` (4 tests: basic, with liabilities, decrease, sponsorship) |
| P1-7 | Available balance/limit | **DONE** | `lib.rs` (3 tests: comprehensive balance, limit, sponsorship combos) |

#### P2 - Medium (state management correctness) - ALL DONE

| ID | Test | Status | Rust Location |
|----|------|--------|---------------|
| P2-1 | Delta round-trip stress test | **DONE** | `delta.rs:test_delta_round_trip_stress`, `test_delta_interleaved_operations` |
| P2-2 | Create entry edge cases | **DONE** | `delta.rs:test_create_on_existing_created_overwrites`, `test_create_on_existing_updated_keeps_original_previous` |
| P2-3 | Erase config entry prevention | **DONE** | `delta.rs:test_cannot_delete_config_setting`, `test_config_setting_create_and_update_allowed` + production code validation |
| P2-4 | Load entry when erased | **DONE** | `delta.rs:test_deleted_entry_shows_as_deleted_in_delta`, `test_created_then_deleted_vanishes`, `test_deleted_entry_previous_preserved`; `snapshot.rs:test_snapshot_entry_not_found`, `test_snapshot_selective_entries` |
| P2-5 | Restored keys tracking | **DONE** | `execution.rs:test_extract_hot_archive_restored_keys_*` (4 tests: actual indices, no soroban data, empty indices, accumulation pattern) |
| P2-6 | LedgerCloseMeta structural validation | **DONE** | `ledger_close_integration.rs:test_ledger_close_meta_structural_validation`, `test_ledger_close_meta_with_scp_history` |

#### P3 - Low (nice-to-have) - DONE or N/A

| ID | Test | Status | Rust Location |
|----|------|--------|---------------|
| P3-1 | Pool share trust line queries | **DONE** | `stellar-core-bucket/tests/test_pool_share_query.rs` (6 tests) |
| P3-2 | Multiple ledger closes | **DONE** | `ledger_close_integration.rs:test_multiple_consecutive_ledger_closes` |
| P3-3 | Read-only semantics | **DONE** | `snapshot.rs:test_snapshot_read_is_side_effect_free` |
| P3-4 | Offer cache eviction | **N/A** | Rust uses in-memory `OfferIndex` rebuilt per close, no eviction needed |

### Remaining Partial Coverage

| # | C++ Test | Status | Notes |
|---|----------|--------|-------|
| 1.2 | Header persistence/reload | **PARTIAL** | Header hash stability tested; SQL persistence N/A (no SQL backend) |
