# Known Issues

This document tracks known issues in rs-stellar-core that affect network synchronization and consensus participation.

## 1. Buffered Gap After Catchup (Critical)

**Status:** Unresolved
**Severity:** Critical - Prevents real-time sync
**Component:** Catchup / Herder

### Description
After catchup completes to a checkpoint ledger, the node cannot close subsequent ledgers because the required transaction sets (tx_sets) are no longer available from peers.

### Symptoms
- Node stuck at checkpoint+1 ledger (e.g., `current_ledger=430400`, `first_buffered=430401`)
- Continuous "DontHave for TxSet" messages from peers
- Buffer keeps growing while the gap remains
- Repeated catchup attempts that skip because target is already past

### Root Cause
1. Catchup completes to checkpoint ledger N
2. Node advances to ledger N+1
3. To close ledger N+2, node needs its tx_set
4. Node requests tx_set from peers
5. Peers respond "DontHave" - tx_set is too old (peers only keep ~12 recent slots)
6. Without tx_set, ledger cannot close
7. Catchup system detects gap, tries to catchup to latest checkpoint
8. Latest checkpoint <= current ledger, so catchup is skipped
9. Cycle repeats indefinitely

### Potential Fixes
1. Implement ledger replay from history archive (fetch tx_sets from archive, not peers)
2. Fast-forward past the gap using EXTERNALIZE messages when tx_sets are unavailable
3. Catch up to a future checkpoint instead of the latest available one

---

## 2. Bucket List Hash Divergence (Critical)

**Status:** ~46% of checkpoint segments work correctly
**Severity:** Critical - Causes header AND transaction execution failures
**Component:** Bucket List
**Last Verified:** 2026-01-18

### Current State
Transaction execution achieves **100% parity** on segments with correct bucket list state. The previously reported "157 mismatches" were caused by bucket list divergence corrupting state, not CPU metering differences.

**Important**: Bucket list divergence causes downstream transaction failures (e.g., Payment(Underfunded) at ledger 10710). When bucket list state diverges, subsequent transactions may see different account balances or entry states, leading to different execution results.

Bucket list hash verification shows checkpoint-specific behavior:
- **46% of segments**: Perfect bucket list parity (0 header mismatches)
- **54% of segments**: Bucket list hash divergence

### Key Findings
- Divergence starts **mid-segment**, not at checkpoint boundaries
- This suggests an issue with bucket list state evolution after restoration
- The merge logic itself has been verified correct through unit testing
- HAS (History Archive State) restoration handles states 0 and 1 correctly

### Segments with Issues
Segments 2, 9, 10, 12, 14, 15, 17, and others show divergence. See `TESTNET_VERIFICATION_STATUS.md` for full details.

### Investigation Notes
- Merge argument order verified correct: OLD (level's curr) first, NEW (incoming) second
- Spill flow matches C++ stellar-core
- Hot archive bucket list handling may need further investigation for Protocol 23+

---

## 3. Liquidity Pool State Overwrite During Loading (RESOLVED)

**Status:** Fixed
**Severity:** N/A - Issue resolved
**Component:** Liquidity Pool / Execution
**Fixed:** 2026-01-18

### Description
PathPaymentStrictReceive operations via liquidity pools showed different `amount_bought` values compared to C++ stellar-core. At ledger 20226 TX 2: our `amount_bought` was 2,289,449,975 vs C++ 2,291,485,078.

### Root Cause
The `load_liquidity_pool` function in `execution.rs` was unconditionally loading pool entries from the bucket-list snapshot, **overwriting** any state that had been updated via CDP sync between transactions.

When verification mode syncs state with CDP metadata after each transaction (to ensure subsequent transactions see correct state), the pool reserves were updated. However, when the next transaction's path payment operation called `load_path_payment_pools`, it reloaded the pool from the immutable snapshot, discarding the CDP-synced state.

**Example flow before fix:**
1. TX 0 (PathPaymentStrictSend) modifies pool: XLM=1,124,681,177,663 → 1,125,181,177,663
2. CDP sync updates pool in state to 1,125,181,177,663
3. TX 2 (PathPaymentStrictReceive) calls `load_liquidity_pool`
4. `load_liquidity_pool` loads from snapshot → **overwrites** with OLD value 1,124,681,177,663
5. Path payment computes wrong result using stale reserves

### Resolution
Fixed `load_liquidity_pool` in `execution.rs` to check if the pool already exists in state before loading from snapshot:

```rust
pub fn load_liquidity_pool(...) -> Result<Option<LiquidityPoolEntry>> {
    // Check if already loaded in state - don't overwrite with snapshot data
    if let Some(pool) = self.state.get_liquidity_pool(pool_id) {
        return Ok(Some(pool.clone()));
    }
    // ... load from snapshot only if not in state
}
```

This matches the pattern used by `load_account`, `load_trustline`, `load_offer`, and other entry loading functions.

### Affected Transactions
- Ledger 20226 TX 2: PathPaymentStrictReceive via XLM/USDC pool

### Verification
After fix: 41,679 transactions in range 20000-40000 verified with 0 mismatches (100% parity).

---

## 4. InvokeHostFunction Resource Limit Failures (RESOLVED)

**Status:** Fixed
**Severity:** N/A - Issue resolved
**Component:** Soroban Host
**Fixed:** 2026-01-18

### Description
Some InvokeHostFunction transactions failed with `ResourceLimitExceeded` in our code but succeeded in C++ stellar-core.

### Root Cause
The WASM module pre-compilation budget was too limited. When pre-compilation failed due to budget constraints, the host had to compile the module during transaction execution. This extra compilation cost (~110K CPU instructions) pushed transactions over their specified instruction limit.

Specifically:
1. C++ stellar-core uses `SharedModuleCacheCompiler` which compiles WASM **without any budget metering**
2. Our `WasmCompilationContext` used `Budget::default()` which has limited resources
3. When pre-compilation failed with `Error(Budget, ExceededLimit)`, the module wasn't cached
4. During transaction execution, the host compiled the module within the transaction's budget
5. This extra compilation cost caused the transaction to exceed its specified CPU limit

### Resolution
Fixed in `host.rs` by increasing the `WasmCompilationContext` budget limits from default (~100M CPU) to very high limits (10B CPU, 1GB memory). This ensures pre-compilation never fails due to budget constraints, matching C++ behavior.

```rust
// Before: Budget::default() with limited resources
// After: Very high limits to match C++ unmetered compilation
let budget = Budget::try_from_configs(
    10_000_000_000,      // 10 billion CPU instructions
    1_000_000_000,       // 1 GB memory
    Default::default(),
    Default::default(),
).unwrap_or_else(|_| Budget::default());
```

### Affected Ledgers
- Ledger 26961 TX 2: USDC `transfer` function call
- Ledger 26962, 26963, 26976, 26982, 27057: Similar InvokeHostFunction transactions

### Verification
After fix: 223 transactions in range 26961-27060 verified with 0 mismatches (100% parity)

---

## 5. Ed25519SignedPayload Extra Signer Verification (RESOLVED)

**Status:** Fixed
**Severity:** N/A - Issue resolved
**Component:** Signature Verification
**Fixed:** 2026-01-18

### Description
Transactions with `extra_signers` preconditions using `Ed25519SignedPayload` signer keys were failing with `BadAuthExtra` even when signatures were valid.

### Root Cause
Two bugs in `has_signed_payload_signature()`:

1. **Wrong hint calculation**: Used just the public key hint instead of XOR of pubkey hint and payload hint (per C++ `SignatureUtils::getSignedPayloadHint`)

2. **Wrong signature verification**: Verified signature against `SHA256(tx_hash || payload)` instead of the raw payload bytes (per CAP-0040)

### Resolution
Fixed in `execution.rs`, `validation.rs`, and `signature_checker.rs` to:
- Calculate hint as `pubkey_hint XOR payload_hint`
- Verify signature against raw payload bytes using `stellar_core_crypto::verify()`

### Affected Ledgers
- Ledger 11725 TX 0: ManageData with Ed25519SignedPayload extra signer
- Ledger 11776: Similar transaction

---

## 6. Soroban CPU Metering Difference (RESOLVED)

**Status:** Fixed
**Severity:** N/A - Issue resolved
**Component:** Soroban Host
**Fixed:** 2026-01-18

### Description
Previously, our soroban-env-host appeared to consume ~10-15% more CPU instructions than C++ stellar-core for identical operations, causing some transactions to fail with `ResourceLimitExceeded` instead of `Trapped`.

### Resolution
Investigation revealed that the "157 mismatches" previously reported were **not caused by CPU metering differences**. They were caused by **bucket list divergence** which corrupted ledger state, leading to different transaction results.

When running verification on segments with correct bucket list state:
- **30000-36000**: 14,651 transactions, 100% match
- **50000-60000**: 13,246 transactions, 100% match
- **70000-75000**: 9,027 transactions, 100% match
- **100000-110000**: 37,744 transactions, 100% match

Both C++ stellar-core and rs-stellar-core use the same Rust soroban-env-host crate (same git revision), so CPU consumption is identical when given identical inputs.

### Root Cause of Original Report
The original "CPU metering differences" were misattributed. The actual cause was bucket list divergence (Issue #2 above) which caused:
1. Different account balances seen during transaction execution
2. Different entry states (expired vs live)
3. Leading to different execution paths and results

**Fixing the bucket list divergence (Issue #2) will eliminate all transaction execution mismatches.**

---

## 7. Credit Asset Self-Payment Order of Operations (RESOLVED)

**Status:** Fixed
**Severity:** N/A - Issue resolved
**Component:** Payment Operation
**Fixed:** 2026-01-18

### Description
Self-payments (source == destination) for credit assets with zero balance were failing with `Payment(Underfunded)` instead of succeeding.

### Root Cause
The order of operations in `execute_credit_payment` was incorrect. The original code:
1. Checked destination trustline authorization and room
2. Checked source trustline authorization and balance → **FAILED** with 0 balance
3. Credited destination
4. Debited source

The C++ stellar-core uses a different order via `PathPaymentStrictReceive`:
1. Credits destination first (`updateDestBalance`)
2. Then checks and debits source (`updateSourceBalance`)

For self-payments where source == dest, both operations affect the **same trustline**. By crediting first, the balance becomes available for the subsequent debit check.

### Resolution
Reordered `execute_credit_payment` in `payment.rs` to:
1. Check destination trustline authorization and room
2. **Credit destination** (mutates the trustline)
3. Check source trustline authorization and balance (sees the credited amount for self-payments)
4. Debit source

Added rollback logic to restore destination credit if source checks fail.

### Affected Ledgers
- Ledger 11143 TX 2: Self-payment of 20,000 USDZ
- Ledger 11264, 11381, 11396: Similar self-payment transactions

### Verification
After fix: 611 transactions in range 11100-11400 verified with 0 mismatches.

---

## 8. ClaimClaimableBalance Issuer NoTrust (RESOLVED)

**Status:** Fixed
**Severity:** N/A - Issue resolved
**Component:** Claimable Balance
**Fixed:** 2026-01-18

### Description
Three transactions failed with `ClaimClaimableBalance(NoTrust)` instead of `Success` when the claimant was the issuer of the claimed asset.

### Root Cause
In C++ stellar-core, `TrustLineWrapper` has special handling for issuers via `IssuerImpl`:
- When `getIssuer(asset) == accountID`, creates an `IssuerImpl` instead of loading a trustline
- `IssuerImpl` always returns `true` for existence/authorization, `INT64_MAX` for balance
- This allows issuers to receive their own asset without a trustline

Our Rust code was missing this issuer handling - we always tried to load a trustline, which returns `None` for issuers (they don't have trustlines for their own assets).

### Resolution
Added issuer check in `execute_claim_claimable_balance`:
```rust
if source == issuer {
    // Issuer claiming their own asset: no trustline update needed
    // (tokens are effectively burned/returned to issuer)
} else {
    // Non-issuer: check trustline exists
    ...
}
```

### Affected Ledgers
- Ledger 37272 TX 0: Issuer claiming USDPEND claimable balance
- Ledger 37307 TX 0: Same issuer claiming claimable balance
- Ledger 37316 TX 1: Same issuer claiming claimable balance

### Verification
After fix: 481 transactions in range 37040-37320 verified with 0 mismatches (InvokeHostFunction issue at ledger 37046 also resolved - see Issue #9).

---

## 9. Soroban Archived Entry TTL Restoration (RESOLVED)

**Status:** Fixed
**Severity:** N/A - Issue resolved
**Component:** Soroban Host
**Fixed:** 2026-01-18

### Description
InvokeHostFunction transactions that restored archived entries (ContractData, ContractCode) from the bucket list were failing with `InvokeHostFunction(Trapped)` instead of succeeding.

### Root Cause
When building the storage map for Soroban execution, archived entries being restored need a TTL (Time-To-Live) value. Our code was providing `live_until_ledger_seq: 0` for entries without an existing TTL.

The soroban-env-host's `build_storage_map_from_xdr_ledger_entries` validates that:
```rust
if ttl_entry.live_until_ledger_seq < ledger_num {
    return Err(Error::from_type_and_code(
        ScErrorType::Storage,
        ScErrorCode::InternalError,
    ).into());
}
```

Since `0 < current_ledger`, the host rejected these entries with `Storage InternalError`, causing the transaction to fail with `Trapped`.

### Resolution
Fixed in `host.rs` (P24 and P25 implementations) and `protocol/p24.rs` to provide `live_until_ledger_seq: current_ledger` instead of `0` for archived entries being restored:

```rust
} else if needs_ttl {
    // For archived entries being restored, provide a TTL at the current ledger.
    // The host validates that TTL >= current_ledger, so we can't use 0 or an expired value.
    // The actual TTL extension happens as part of the restoration operation.
    let ttl_entry = TtlEntry {
        key_hash,
        live_until_ledger_seq: current_ledger, // Use current ledger as minimum valid TTL
    };
```

### Affected Ledgers
- Ledger 37046 TX 1: USDC `transfer` function call restoring archived ContractData entry

### Verification
After fix: 21,999 transactions in range 30000-40000 verified with 0 mismatches (100% parity).

---

## 10. ManageSellOffer OpNotSupported Bug (NEW)

**Status:** Unresolved
**Severity:** Medium - Affects specific ManageSellOffer operations
**Component:** Offer Management
**Discovered:** 2026-01-19

### Description
At ledger 237057, a ManageSellOffer operation returns `OpNotSupported` in our code but succeeds in C++ stellar-core with `offer: Deleted`.

### Details
```
Ledger 237057 TX 0:
  - Our result: OpNotSupported (transaction failed)
  - CDP result: ManageSellOffer(Success { offers_claimed: [], offer: Deleted })
```

This segment has **0 header mismatches**, meaning the bucket list state is correct. This is a genuine execution bug, not caused by state divergence.

### Root Cause
Under investigation. The operation appears to be a deletion of an existing offer that our code incorrectly rejects as not supported.

### Affected Ledgers
- Ledger 237057 TX 0

---

## 11. InvokeHostFunction InsufficientRefundableFee Bug (NEW)

**Status:** Unresolved
**Severity:** Medium - Causes successful transactions to fail
**Component:** Soroban Host / Fee Handling
**Discovered:** 2026-01-19

### Description
At ledger 342737, an InvokeHostFunction transaction fails with `InsufficientRefundableFee` in our code but succeeds in C++ stellar-core.

### Details
```
Ledger 342737 TX 3:
  - Our result: InvokeHostFunction(InsufficientRefundableFee)
  - CDP result: InvokeHostFunction(Success(Hash(...)))
```

### Root Cause
Under investigation. Our code is rejecting a transaction with insufficient refundable fee when C++ stellar-core accepts it. This may indicate:
1. Different fee calculation
2. Different refundable fee validation threshold
3. Different handling of fee refunds

### Affected Ledgers
- Ledger 342737 TX 3

---

## 12. InvokeHostFunction Trapped vs ResourceLimitExceeded (Under Investigation)

**Status:** Under Investigation
**Severity:** Low - Both fail, just different error codes
**Component:** Soroban Host
**Discovered:** 2026-01-19

### Description
Some InvokeHostFunction transactions fail with `Trapped` in our code but `ResourceLimitExceeded` in C++ stellar-core. Both are failures, but the error code differs.

### Details
```
Ledger 152692 TX 2:
  - Our result: InvokeHostFunction(Trapped)
  - CDP result: InvokeHostFunction(ResourceLimitExceeded)

Ledger 327722 TX 6:
  - Our result: InvokeHostFunction(Trapped)
  - CDP result: InvokeHostFunction(ResourceLimitExceeded)
```

### Root Cause
The transactions fail in both implementations, but the error detection order differs. This could be:
1. Host detecting trap condition before resource limit check
2. Different order of validation checks
3. Edge case in resource tracking

This is related to the previously fixed Issue #4 but occurring in different ledgers. May require further investigation of host error prioritization.

### Affected Ledgers
- Ledger 152692 TX 2
- Ledger 327722 TX 6

---

## 13. ManageSellOffer/ManageBuyOffer Orderbook State Divergence (Under Investigation)

**Status:** Under Investigation - Likely Bucket List Induced
**Severity:** Low - May be caused by bucket list divergence
**Component:** Offer Management / Orderbook
**Discovered:** 2026-01-19

### Description
Several ManageSellOffer and ManageBuyOffer transactions claim different offers than C++ stellar-core. Both succeed but with different `offers_claimed` results.

### Details
```
Ledger 201477 TX 2:
  - Our offers_claimed: [offer_id: 8071, 8072]
  - CDP offers_claimed: [offer_id: 8072, 8065, 8003, 7975]

Ledger 325512 TX 4:
  - Our offers_claimed: [offer_id: 13058 amount: 318136]
  - CDP offers_claimed: [offer_id: 13058 amount: 203789]

Ledger 332809 TX 4:
  - Our offers_claimed: [offer_id: 13470, 13472, 13474]
  - CDP offers_claimed: [offer_id: 13480, 13482, 13484]
```

### Root Cause
Likely caused by bucket list divergence. The segments containing these ledgers have significant header mismatches, indicating the orderbook state (offers) differs due to corrupted bucket list state.

**Note**: These are likely NOT genuine execution bugs but rather symptoms of bucket list divergence (Issue #2). When the bucket list diverges, offer entries have different values, leading to different orderbook matching results.

### Affected Ledgers
- Ledger 201477, 201755 (segment 21 - has header mismatches)
- Ledger 325512 (segment 33 - has header mismatches)
- Ledger 332809 (segment 34 - has header mismatches)

---

## 14. InvokeHostFunction Refundable Fee Inconsistency (NEW - Bidirectional)

**Status:** Unresolved
**Severity:** High - Fee validation differs in both directions
**Component:** Soroban Host / Fee Handling
**Discovered:** 2026-01-19

### Description
InvokeHostFunction transactions show inconsistent refundable fee behavior compared to C++ stellar-core. In some cases we accept transactions that CDP rejects, and in other cases we reject transactions that CDP accepts.

### Details
**Case 1: We succeed, CDP fails (ledger 390407)**
```
Ledger 390407 TX 9:
  - Our result: InvokeHostFunction(Success(...))
  - CDP result: InvokeHostFunction(InsufficientRefundableFee)

Ledger 390407 TX 10:
  - Our result: InvokeHostFunction(Success(...))
  - CDP result: InvokeHostFunction(InsufficientRefundableFee)
```

**Case 2: We fail, CDP succeeds (ledger 342737)**
```
Ledger 342737 TX 3:
  - Our result: InvokeHostFunction(InsufficientRefundableFee)
  - CDP result: InvokeHostFunction(Success(...))
```

### Root Cause
Our refundable fee calculation differs from C++ stellar-core. This could be:
1. Different calculation of required refundable fee
2. Different timing of when the fee check is performed
3. Different handling of fee refund logic

This is a critical parity issue as it affects which transactions are accepted/rejected.

### Affected Ledgers
- Ledger 342737 TX 3 (we fail, should succeed)
- Ledger 390407 TX 9, 10 (we succeed, should fail)

---

## 15. ManageSellOffer TooManySubentries Check Missing (NEW)

**Status:** Unresolved
**Severity:** Critical - We accept invalid transactions
**Component:** Offer Management / Subentry Counting
**Discovered:** 2026-01-19

### Description
At ledger 407293, a transaction with many ManageSellOffer operations succeeds in our code but fails in C++ stellar-core with `OpTooManySubentries` starting at operation 48.

### Details
```
Ledger 407293 TX 1:
  - Our result: TxSuccess (all 56 operations succeed)
  - CDP result: TxFailed (ops 0-47 succeed, ops 48-55 fail with OpTooManySubentries)
```

The transaction attempts to create 56 new offers for the same account. C++ stellar-core correctly rejects operations 48+ because the account would exceed its subentry limit. Our code does not enforce this limit.

### Root Cause
Our ManageSellOffer implementation doesn't properly check or enforce the account subentry limit. In Stellar, each offer counts as a subentry, and accounts have a limit based on their number of signers and other factors.

The formula for max subentries is typically:
- Base reserve accounts for 2 base subentries
- Additional subentries require additional reserve

When an account reaches its subentry limit, new offer creation should fail with `OpTooManySubentries`.

### Affected Ledgers
- Ledger 407293 TX 1

---

## Summary: Genuine Execution Bugs vs Bucket-List Induced

### Genuine Bugs (tx_only mismatches in segments with clean bucket list OR consistent behavior)

| Issue | Ledger | Description |
|-------|--------|-------------|
| #10 | 237057 | ManageSellOffer OpNotSupported vs Success (0 header mismatches) |
| #14 | 342737, 390407 | InvokeHostFunction refundable fee inconsistency |
| #15 | 407293 | ManageSellOffer TooManySubentries not enforced |

### Likely Bucket-List Induced (segments with header mismatches)

| Issue | Ledgers | Description |
|-------|---------|-------------|
| #12 | 152692, 327722 | InvokeHostFunction Trapped vs ResourceLimitExceeded |
| #13 | 201477, 201755, 325512, 332809 | Orderbook claims different offers |

---

## 16. SetTrustLineFlags CantRevoke vs Success (NEW)

**Status:** Unresolved
**Severity:** Medium - Legitimate operations rejected
**Component:** TrustLine Flags
**Discovered:** 2026-01-19

### Description
At ledger 416662, a SetTrustLineFlags operation returns `CantRevoke` in our code but succeeds in C++ stellar-core.

### Details
```
Ledger 416662 TX 3:
  - Our result: SetTrustLineFlags(CantRevoke)
  - CDP result: SetTrustLineFlags(Success)
```

### Root Cause
Our SetTrustLineFlags implementation may have incorrect logic for determining when a trustline's flags can be modified. The `CantRevoke` error is typically returned when trying to revoke authorization on a trustline where the issuer doesn't have the appropriate flags set.

### Affected Ledgers
- Ledger 416662 TX 3

---

## 17. Missing Persistent WASM Module Cache (Performance)

**Status:** Unresolved
**Severity:** High - Causes 10x+ slowdown in Soroban-heavy segments
**Component:** Soroban Host / WASM Compilation
**Discovered:** 2026-01-19

### Description
Verification of later testnet segments (380k+ ledgers) runs ~10x slower than earlier segments despite similar transaction counts. Processing rate drops from ~3,000 TX/min to ~300 TX/min.

### Details
| Segment | Ledger Start | TXs | Duration | TX/min |
|---------|--------------|-----|----------|--------|
| 20 | 190,064 | 33,288 | 604s | 3,306 |
| 35 | 340,064 | 33,025 | 919s | 2,156 |
| 39 | 380,064 | 35,459 | 6,965s | 305 |
| 44 | 430,064 | 37,452 | 7,932s | 283 |

### Root Cause
Our implementation builds a **new ModuleCache for every transaction** in `build_module_cache_for_footprint()`. This means:
1. Every Soroban transaction creates a fresh `ModuleCache`
2. All WASM modules in the footprint are compiled from scratch
3. Compiled modules are discarded after the transaction

C++ stellar-core uses a `SharedModuleCacheCompiler` that:
1. Persists the module cache across transactions via `app.getLedgerManager().getModuleCache()`
2. `ThreadParallelApplyLedgerState` stores `mModuleCache` and reuses it
3. Compiled WASM modules are cached and reused for subsequent transactions

If the same contract (e.g., USDC) is called 1000 times in a segment, we compile its WASM 1000 times instead of once.

### Affected Code
- `crates/stellar-core-tx/src/soroban/host.rs`: `build_module_cache_for_footprint()` and `build_module_cache_for_footprint_p25()`
- Need to add persistent cache at verification/execution level

### Fix Approach
1. Create a persistent `ModuleCache` at the segment/ledger-range level
2. Pass the cache into `invoke_host_function_p24`/`invoke_host_function_p25`
3. Populate cache incrementally as new contracts are encountered
4. Match C++ `SharedModuleCacheCompiler` behavior

---

### Priority Order for Fixes

1. **Critical**: #15 (TooManySubentries) - We accept invalid transactions
2. **High**: #14 (Refundable Fee) - Bidirectional fee validation mismatch
3. **High**: #17 (Module Cache) - 10x performance degradation
4. **Medium**: #10 (OpNotSupported) - Legitimate operations rejected
5. **Medium**: #16 (SetTrustLineFlags CantRevoke) - Legitimate operations rejected
6. **Low**: #12, #13 - May resolve when bucket list is fixed
