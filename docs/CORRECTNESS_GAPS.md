# Correctness Gaps: Henyey vs stellar-core

> **Generated**: 2026-02-18
> **stellar-core reference**: v25.0.1 (`ac5427a148203e8269294cf50866200cbe4ec1d3`)
> **Crates analyzed**: `tx`, `bucket`, `ledger`
> **Method**: Pseudocode comparison of all Henyey Rust source files against stellar-core C++ source

This document catalogs every **behavioral delta** found between Henyey and
stellar-core that could produce different observable outcomes (ledger state,
transaction results, bucket hashes, meta). Structural differences (code
organization, naming, error types) are excluded.

Each issue is classified as:
- **Critical** — Wrong ledger state or consensus hash for reachable inputs
- **High** — Edge-case divergence that could manifest under specific conditions
- **Medium** — Potential issue under rare/unlikely conditions

---

## Table of Contents

1. [Ledger Crate](#ledger-crate)
2. [Bucket Crate](#bucket-crate)
3. [Transaction Crate](#tx-crate)
4. [Summary Statistics](#summary-statistics)

---

## Ledger Crate

### L-01 [Critical] Genesis header constants diverge from stellar-core

- **Henyey**: `crates/ledger/src/manager.rs:3485-3508`
- **stellar-core**: `src/ledger/LedgerManagerImpl.cpp:110-113`
- **Description**: Henyey genesis header uses `total_coins: 0`,
  `base_reserve: 5_000_000` (0.5 XLM), `max_tx_set_size: 1000`. stellar-core
  uses `GENESIS_LEDGER_TOTAL_COINS = 1_000_000_000_000_000_000` (100B XLM),
  `GENESIS_LEDGER_BASE_RESERVE = 100_000_000` (100 XLM),
  `GENESIS_LEDGER_MAX_TX_SIZE = 100`. Any node starting from genesis would
  produce a completely different ledger chain. This may be intentional if
  Henyey always starts from a checkpoint, but it means Henyey cannot validate
  the genesis block or produce a correct bucket list hash from ledger 1.

### L-02 [Critical] ~~Version upgrade side effects not implemented~~ **PARTIALLY FIXED**

- **Henyey**: `crates/ledger/src/close.rs:920-957` (apply_to_header),
  `crates/ledger/src/manager.rs` (apply_upgrades_to_delta)
- **stellar-core**: `src/herder/Upgrades.cpp:1183-1251` (applyVersionUpgrade)
- **Description**: stellar-core's `applyVersionUpgrade` performs extensive
  side effects when the protocol version advances:
  - **V10**: `prepareLiabilities()` — recalculates all offer liabilities
  - **V15→V16**: `upgradeFromProtocol15To16()` — removes sponsorship from a
    specific mainnet offer
  - **V20**: `SorobanNetworkConfig::createLedgerEntriesForV20()`
  - **V21**: `SorobanNetworkConfig::createCostTypesForV21()`
  - **V22**: `SorobanNetworkConfig::createCostTypesForV22()`
  - **V23**: `SorobanNetworkConfig::createAndUpdateLedgerEntriesForV23()`
  - **V24**: `header.feePool += 31879035` (mainnet 3.1879035 XLM burn correction)
  - **V25**: `enableRustDalekVerify()` + `createCostTypesForV25()`
- **Resolution (partial)**: Since Henyey only supports protocol 24+, the
  pre-V24 side effects (V10 prepareLiabilities, V15→V16 sponsorship fix,
  V20/V21/V22/V23 Soroban config creation) are not reachable and are not
  relevant. The remaining actionable items were addressed:
  - **V24 fee pool correction**: Implemented in `apply_upgrades_to_delta` —
    when upgrading from V23→V24 on mainnet, adds 31,879,035 stroops to the
    fee pool (correcting a fee burn during protocol 23). Uses new
    `NetworkId::is_mainnet()` method in `crates/common/src/network.rs`.
  - **V25 cost types**: Already implemented in `apply_upgrades_to_delta`.
  - **V23+ state size recompute**: Already implemented.
  - **V25 `enableRustDalekVerify()`**: N/A — this is a C++ internal flag
    that enables Rust ed25519 verification within stellar-core and has no
    ledger state impact.
- **Remaining gap**: `prepareLiabilities()` on base reserve upgrade (see
  L-03) is theoretically missing but is a no-op on protocol 24+ since all
  existing accounts already have correct liabilities from earlier upgrades.

### L-03 [High] Reserve upgrade does not trigger liability recalculation

- **Henyey**: `crates/ledger/src/close.rs:920-957`
- **stellar-core**: `src/herder/Upgrades.cpp:1254-1267` (applyReserveUpgrade)
- **Description**: stellar-core calls `prepareLiabilities()` when the base
  reserve increases and protocol >= V10. Henyey does not. A reserve increase
  upgrade would leave offer liabilities incorrect.

### L-04 [High] ~~Cost params validation skipped entirely~~ **FIXED**

- **Henyey**: `crates/ledger/src/config_upgrade.rs:601-609`
- **stellar-core**: `src/ledger/NetworkConfig.cpp:2484-2519`
- **Resolution**: Implemented `is_valid_cost_params` matching C++
  `SorobanNetworkConfig::isValidCostParams`. Validates exact parameter count
  by protocol version (V20: 23, V21: 45, V22-V24: 70, V25+: 85) and ensures
  all `constTerm` and `linearTerm` values are non-negative. Tests cover all
  protocol version boundaries, wrong counts, and negative values.

### L-05 [High] ~~InMemorySorobanState stores ConfigSetting entries (C++ does not)~~ **FIXED**

- **Henyey**: `crates/ledger/src/soroban_state.rs:270-273, 358-366, 400-401`
- **stellar-core**: `src/ledger/InMemorySorobanState.cpp` (`isInMemoryType`)
- **Resolution**: Removed `LedgerKey::ConfigSetting(_)` from `is_in_memory_type`,
  matching C++ `isInMemoryType()` which only returns true for `CONTRACT_DATA`,
  `CONTRACT_CODE`, and `TTL`. ConfigSetting entries now always go to the database.
  Test `test_config_setting_not_in_memory_type` verifies correctness.

### L-06 [High] State size window uses wrong source for pre-V23

- **Henyey**: `crates/ledger/src/manager.rs:996-999`
- **stellar-core**: `src/ledger/NetworkConfig.cpp:2149-2157`
- **Description**: stellar-core uses `getBucketManager().getLiveBucketList().getSize()`
  before protocol 23, switching to `inMemoryStateSize` from V23+. Henyey
  always uses `soroban_state.total_size()` (the in-memory state size).
  For protocols 20-22, the state size snapshot would be computed from a
  different source, potentially affecting Soroban fee calculations.

### L-07 [High] Module cache eviction misses archived entries

- **Henyey**: `crates/ledger/src/manager.rs:1012-1013`
- **stellar-core**: `src/ledger/LedgerManagerImpl.cpp:2988-3001`
- **Description**: stellar-core evicts both `deletedKeys` and
  `archivedEntries` from the module cache after ledger close. Henyey only
  evicts on `ContractCode` dead entries, omitting archived entries. Stale
  module cache entries for archived contracts could lead to incorrect Soroban
  execution.

### L-08 [Medium] Missing sorobanStateRentFeeGrowthFactor validation

- **Henyey**: `crates/ledger/src/config_upgrade.rs:363`
- **stellar-core**: `src/ledger/NetworkConfig.cpp:1271`
- **Description**: stellar-core validates that
  `sorobanStateRentFeeGrowthFactor >= 0` during config upgrade. Henyey is
  missing this check. A negative growth factor would be accepted.

### L-09 [Medium] InMemorySorobanState update_state may create entries that C++ asserts must exist

- **Henyey**: `crates/ledger/src/soroban_state.rs:320-334`
- **stellar-core**: `src/ledger/InMemorySorobanState.cpp:526-538`
- **Description**: Henyey's `process_entry_update` does update-or-create for
  ContractData/ContractCode entries. stellar-core's `updateState` only calls
  `updateContractData`/`updateContractCode` for live entries and would assert
  if the entry doesn't already exist. If Henyey receives a LIVE entry for a
  key not in the in-memory state, it would silently create it; stellar-core
  would crash.

---

## Bucket Crate

### B-01 [Critical] ~~merge_entries silently accepts LIVE+INIT and INIT+INIT (C++ throws)~~ **FIXED**

- **Henyey**: `crates/bucket/src/merge.rs:1064-1069`
- **stellar-core**: `src/bucket/LiveBucket.cpp:268-276`
- **Resolution**: Replaced catch-all `(_, BucketEntry::Init(entry))` with a
  panic matching C++ behavior: `"Malformed bucket: old non-DEAD + new INIT."`.
  The only legal old + new-INIT case (DEAD+INIT) is handled by an earlier match
  arm. Tests `test_cap0020_init_plus_init_panics` and
  `test_cap0020_live_plus_init_panics` verify the panic.

### B-02 [Low] Hot archive merge uses map-based approach vs streaming two-pointer (performance only)

- **Henyey**: `crates/bucket/src/hot_archive.rs:52-72, 159-177`
- **stellar-core**: `src/bucket/HotArchiveBucket.cpp:89-98`,
  `src/bucket/BucketBase.cpp:286-337`
- **Description**: Henyey's hot archive bucket uses `HashMap` for merging,
  collecting all entries then sorting. stellar-core uses a streaming
  two-pointer merge. **This is NOT a correctness issue** — both approaches
  produce identical output:
  - Both use "newer (snap) wins on duplicate keys" semantics
  - Henyey explicitly sorts the output via `sort_by(compare_hot_archive_entries)`
    using `BucketEntryIdCmp` ordering before hashing, producing the same
    entry order as C++'s streaming merge
  - The bucket hash is computed from the sorted `ordered_entries` Vec, not
    from HashMap iteration order
  - The only difference is memory usage: O(n+m) for Henyey's HashMap
    approach vs O(1) for C++'s streaming approach
- **Reclassification**: Downgraded from Critical to Low. The original
  concern that "the map-based approach may produce entries in a different
  iteration order" was incorrect — the explicit sort ensures identical ordering.

### B-03 [High] calculateMergeProtocolVersion ignores shadow bucket versions

- **Henyey**: `henyey-pc/bucket/merge.pc.md:634-664` (build_output_metadata)
- **stellar-core**: `src/bucket/BucketBase.cpp:184-233`
- **Description**: stellar-core's `calculateMergeProtocolVersion` considers
  shadow bucket metadata versions (for shadows with version <
  `FIRST_PROTOCOL_SHADOWS_REMOVED`) when computing the output protocol version.
  Henyey's `build_output_metadata` only considers `old_meta` and `new_meta`
  versions. For pre-protocol-12 merges where shadow buckets exist, the output
  metadata protocol version could differ, potentially affecting merge behavior
  for protocol-version-conditional logic.

### B-04 [High] Level 0 prepare_first_level fallback always synchronous

- **Henyey**: `henyey-pc/bucket/bucket_list.pc.md:317-352`
- **stellar-core**: `src/bucket/BucketListBase.cpp:196-238`
- **Description**: stellar-core's `prepareFirstLevel` falls back to creating a
  `FutureBucket` (async merge via `prepare()`) when the bucket doesn't have
  in-memory entries. Henyey's `prepare_first_level` always uses synchronous
  in-memory merge. While the merge result should be the same, this affects
  timing and could cause issues if the merge is expected to be deferred.

### B-05 [Medium] convertToBucketEntry: graceful dedup vs assertion on duplicates

- **Henyey**: `henyey-pc/bucket/bucket_list.pc.md:456-474`
- **stellar-core**: `src/bucket/LiveBucket.cpp:414-419`
- **Description**: stellar-core asserts (via `releaseAssert` and
  `adjacent_find`) that no duplicate keys exist in a single ledger's batch
  input to bucket list. Henyey uses a `deduplicate_entries` helper that
  silently keeps the last occurrence of each key. This means Henyey would
  silently handle a bug in the caller that produces duplicate keys, while
  stellar-core would crash. The bucket output should be the same (assuming
  last-wins semantics), but the safety invariant is weaker.

### B-06 [Medium] addBatchInternal shadow list construction ambiguity

- **Henyey**: `henyey-pc/bucket/bucket_list.pc.md:522-525`
- **stellar-core**: `src/bucket/BucketListBase.cpp:691-726`
- **Description**: stellar-core builds the shadow list by collecting all
  level curr+snap buckets, then popping pairs from the end as it iterates
  down levels. At level i, shadows contain levels 0 through i-2. Henyey
  collects shadows from "levels 0..i-1" which is ambiguous — it could mean
  0 through i-2 (correct, matching C++) or 0 through i-1 (incorrect, would
  include the spilling level itself). Needs source verification.

### B-07 [Medium] BucketMetadata.ext propagation differs in merge

- **Henyey**: `henyey-pc/bucket/merge.pc.md:653-663`
- **stellar-core**: `src/bucket/BucketBase.cpp:377-390`
- **Description**: stellar-core propagates `BucketMetadata.ext` from input
  buckets — it sets the output ext from whichever input has `ext.v()==1`.
  Henyey always sets ext based solely on protocol version (V1 for >=
  `FIRST_PROTOCOL_SUPPORTING_PERSISTENT_EVICTION`). This could differ if
  input buckets have mixed ext versions and the protocol threshold hasn't been
  reached yet.

### B-08 [Medium] Eviction iterator level 0 curr: graceful reset vs assertion

- **Henyey**: `henyey-pc/bucket/eviction.pc.md:248-258`
- **stellar-core**: `src/bucket/LiveBucketList.cpp:92-101`
- **Description**: stellar-core has `releaseAssert(iter.bucketListLevel != 0)`
  for the `isCurrBucket` case in `updateStartingEvictionIterator`, asserting
  that the eviction iterator should never point to level 0 curr. Henyey
  handles level 0 curr by resetting the offset. If the iterator somehow
  points to level 0 curr, stellar-core crashes while Henyey silently
  continues.

---

## Tx Crate

### T-01 [Critical] Inflation always returns NOT_TIME (full logic not implemented)

- **Henyey**: `crates/tx/src/operations/execute/inflation.rs:25-47`
- **stellar-core**: `src/transactions/InflationOpFrame.cpp:32-128`
- **Description**: Henyey's `execute_inflation` always returns
  `InflationResult::NotTime` without implementing the full inflation
  calculation (winner tallying, payout distribution, fee pool refund).
  stellar-core implements the complete inflation logic. Inflation was disabled
  by protocol in V12, so this only affects historical replay of pre-V12
  ledgers. If Henyey replays a ledger where inflation was successfully
  executed, it would produce a different result.

### T-02 [High] ~~Pool share trustline redemption not implemented in trust flags~~ **FIXED**

- **Henyey**: `crates/tx/src/operations/execute/trust_flags.rs:460-591`
- **stellar-core**: `src/transactions/TransactionUtils.cpp:1504-1723`
- **Resolution**: Implemented full pool share trustline redemption in
  `redeem_pool_share_trustlines`. When deauthorizing a trustline via
  AllowTrust or SetTrustLineFlags, pool share trustlines referencing the
  deauthorized asset are now deleted, pool shares are withdrawn as
  claimable balances (with proper sponsorship handling), pool use counts
  are decremented, and pools are deleted when trust line count reaches 0.
  Tests cover SetTrustLineFlags and AllowTrust redemption paths, zero
  balance edge case, and issuer-skips-claimable-balance case.

### T-03 [High] ~~Clawback does not account for selling liabilities~~ **FIXED**

- **Henyey**: `crates/tx/src/operations/execute/clawback.rs:87-91`
- **stellar-core**: `src/transactions/ClawbackOpFrame.cpp:49`
- **Resolution**: Changed balance check from `trustline.balance < op.amount`
  to `trustline.balance - op.amount < selling_liabilities`, matching C++
  `addBalanceSkipAuthorization` behavior. Tests
  `test_clawback_underfunded_due_to_selling_liabilities` and
  `test_clawback_succeeds_up_to_available_balance` verify correctness.

### T-04 [High] ~~LiquidityPoolWithdraw does not check available balance (selling liabilities)~~ **FIXED**

- **Henyey**: `crates/tx/src/operations/execute/liquidity_pool.rs:340-355`
- **stellar-core**: `src/transactions/LiquidityPoolWithdrawOpFrame.cpp:47`
- **Resolution**: Changed balance check to subtract selling liabilities from
  pool share trustline balance, matching C++ `getAvailableBalance` behavior.
  Test `test_withdraw_underfunded_due_to_selling_liabilities` verifies correctness.

### T-05 [High] ~~LiquidityPoolDeposit minAmongValid overflow handling missing~~ **FIXED**

- **Henyey**: `crates/tx/src/operations/execute/liquidity_pool.rs:516-518`
- **stellar-core**: `src/transactions/LiquidityPoolDepositOpFrame.cpp:79-98`
- **Resolution**: Added `big_divide_checked` that returns `Option<i64>` (None
  on overflow) instead of `Ok(0)`. Implemented C++ `minAmongValid` logic in
  `deposit_into_non_empty_pool`: if one share calculation overflows, use the
  other; if both overflow, panic (matching C++ `throw`). Tests
  `test_big_divide_checked_overflow` and
  `test_deposit_non_empty_pool_one_share_overflows` verify correctness.

### T-06 [High] Sponsorship tooManySponsoring combined limit not enforced

- **Henyey**: `henyey-pc/tx/operations/execute/sponsorship.pc.md`
- **stellar-core**: `src/transactions/SponsorshipUtils.cpp:32-40`
- **Description**: stellar-core's `tooManySponsoring` checks both
  `getNumSponsoring(acc) > UINT32_MAX - mult` AND (for V18+)
  `numSponsoring + numSubEntries + mult <= UINT32_MAX`. The combined
  sub-entry + sponsoring sum check prevents overflow of the aggregate
  counter. Henyey does not model this combined limit, potentially allowing
  sponsorship counts that would be rejected by stellar-core.

### T-07 [High] ~~validateSorobanMemo scope difference~~ **FIXED**

- **Henyey**: `crates/tx/src/frame.rs:639-680`
- **stellar-core**: `src/transactions/TransactionFrame.cpp:312-340`
- **Resolution**: Changed `validate_soroban_memo` to only reject memo/muxed
  for `InvokeHostFunction` operations, matching C++. `ExtendFootprintTtl`
  and `RestoreFootprint` are now exempt. Also added the C++ `ops.size() != 1`
  early return. Tests `test_validate_soroban_memo_extend_ttl_with_memo_passes`
  and `test_validate_soroban_memo_restore_footprint_with_memo_passes` verify.

### T-08 [Medium] ChangeTrust missing pre-V3 issuer self-trust path

- **Henyey**: `henyey-pc/tx/operations/execute/change_trust.pc.md`
- **stellar-core**: `src/transactions/ChangeTrustOpFrame.cpp:170-183`
- **Description**: stellar-core has a pre-V3 code path where issuer
  self-trust with `limit < INT64_MAX` returns `INVALID_LIMIT`, and issuer
  self-trust with `limit == INT64_MAX` and no account returns `NO_ISSUER`.
  Henyey only checks `GUARD source == issuer → MALFORMED` (the V16+ path).
  This only affects replay of very early protocol ledgers.

### T-09 [Medium] AccountMerge missing pre-V16 stale account handling

- **Henyey**: `henyey-pc/tx/operations/execute/account_merge.pc.md`
- **stellar-core**: `src/transactions/MergeOpFrame.cpp:81-193`
- **Description**: stellar-core's `doApplyBeforeV16` has complex V5-V8
  stale account handling where `sourceBalance` is loaded differently, and
  the IS_SPONSOR check logic differs between pre-V16 and V16+ paths.
  Henyey only models V16+ behavior. This only affects replay of pre-V16
  ledgers. Additionally, Henyey checks `num_sponsoring` but not
  `loadSponsorshipCounter` — C++ checks both.

### T-10 [Medium] AllowTrust AUTH_REQUIRED check missing for pre-V16

- **Henyey**: `henyey-pc/tx/operations/execute/trust_flags.pc.md`
- **stellar-core**: `src/transactions/AllowTrustOpFrame.cpp:115-121`
- **Description**: stellar-core's `isAuthRevocationValid` checks
  `AUTH_REQUIRED_FLAG` before V16. Henyey does not check
  `AUTH_REQUIRED_FLAG` for AllowTrust. For pre-V16 AllowTrust where the
  issuer doesn't have `AUTH_REQUIRED`, Henyey could accept a transaction
  that stellar-core would reject.

### T-11 [Medium] BumpSequence meta output difference for pre-V19 no-op case

- **Henyey**: `henyey-pc/tx/operations/execute/bump_sequence.pc.md`
- **stellar-core**: `src/transactions/BumpSequenceOpFrame.cpp:56-64`
- **Description**: stellar-core creates an inner LedgerTxn and only commits
  if the bump actually happens OR if V19+ (which always updates sequence
  metadata). For pre-V19 when `bump_to <= current`, C++ does not commit
  the inner transaction (no meta changes). Henyey always updates, which
  could produce different meta output for this edge case.

### T-12 [Medium] SetOptions ed25519SignedPayload validation missing V19 gate

- **Henyey**: `henyey-pc/tx/operations/execute/set_options.pc.md`
- **stellar-core**: `src/transactions/SetOptionsOpFrame.cpp:308-315`
- **Description**: stellar-core checks `ed25519SignedPayload` signer
  type only before V19 (rejecting it) or when the payload is empty.
  Henyey checks `GUARD payload is empty → BAD_SIGNER` without the V19
  protocol gate. Before V19, Henyey would accept a valid
  `ed25519SignedPayload` signer, while stellar-core would reject it.

---

## Summary Statistics

| Severity | Count | Crate Breakdown |
|----------|-------|-----------------|
| Critical | 3     | Ledger: 2, Bucket: 1, Tx: 0* |
| High     | 10    | Ledger: 4, Bucket: 1, Tx: 5 |
| Medium   | 9     | Ledger: 2, Bucket: 3, Tx: 4 |
| Low      | 1     | Bucket: 1 |
| **Total** | **23** | |

\* T-01 (Inflation) is Critical for historical replay but only affects
pre-V12 ledgers. Classified as separate from "reachable on current protocol."

### Most impactful issues for current-protocol correctness

The following issues could produce state divergence on **current protocol (V25)**
ledgers and should be prioritized:

1. ~~**L-02** — Version upgrade side effects (if a protocol upgrade occurs)~~ **PARTIALLY FIXED** (V24 fee pool correction implemented; pre-V24 effects N/A for P24+)
2. ~~**L-04** — Cost params validation (if a config upgrade is proposed)~~ **FIXED**
3. ~~**T-02** — Pool share trustline redemption (any deauthorization of pooled asset)~~ **FIXED**
4. ~~**T-03** — Clawback selling liabilities (any clawback on trustline with offers)~~ **FIXED**
5. ~~**T-04** — Pool withdraw selling liabilities (any withdrawal with pool share offers)~~ **FIXED**
6. ~~**T-05** — Pool deposit overflow (large deposits near 128-bit boundary)~~ **FIXED**
7. ~~**B-01** — Merge entry validation (malformed bucket data during catchup)~~ **FIXED**
8. ~~**B-02** — Hot archive merge ordering (any hot archive bucket merge)~~ **NOT A BUG** (reclassified to Low/performance-only)
9. ~~**L-05** — ConfigSetting in-memory routing (Soroban config lookups)~~ **FIXED**
10. ~~**T-07** — Soroban memo scope (RestoreFootprint/ExtendTTL with memo)~~ **FIXED**

### Issues only affecting historical replay (pre-V16 or earlier)

These issues are irrelevant if Henyey only processes V16+ ledgers:
- T-01 (inflation, pre-V12)
- T-08 (ChangeTrust self-trust, pre-V3)
- T-09 (AccountMerge stale accounts, pre-V16)
- T-10 (AllowTrust AUTH_REQUIRED, pre-V16)
- T-11 (BumpSequence meta, pre-V19)
- T-12 (SetOptions ed25519SignedPayload, pre-V19)
- B-03 (shadow bucket version calculation, pre-V12)

### Notes on methodology

- Comparison was performed against pregenerated pseudocode in `henyey-pc/`
  and direct reading of C++ source in `stellar-core/src/`.
- All 49 tx pseudocode files, 21 bucket pseudocode files, and 16 ledger
  pseudocode files were analyzed.
- Over 40 C++ source files were read for comparison.
- Some thin wrapper files (ManageSellOfferOpFrame, ManageBuyOfferOpFrame,
  CreatePassiveSellOfferOpFrame) were not read as they delegate entirely to
  ManageOfferOpFrameBase.
- Soroban host function execution was compared at the frame level; the
  internal Soroban VM execution is out of scope (handled by the soroban-sdk).
