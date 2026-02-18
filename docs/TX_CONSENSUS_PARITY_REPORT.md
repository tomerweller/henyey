# Consensus Parity Report: `crates/tx` vs stellar-core v25

**Date:** 2026-02-17
**Scope:** Full pseudocode comparison of `crates/tx` (Henyey) against `.upstream-v25/src/transactions/` (stellar-core v25 / protocol 25)
**Method:** Side-by-side pseudocode comparison of all 24 Rust source files against their C++ counterparts

---

## Summary

28 behavioral deltas were identified across the transaction execution pipeline. Of these:

- **6 Critical** — will cause ledger state divergence on real-world traffic
- **8 High** — will cause divergence under specific but plausible conditions
- **9 Medium** — will cause divergence in edge cases or affect result XDR fidelity
- **5 Low** — minor result code differences unlikely to affect consensus

All file references use the format `file:line` relative to `crates/tx/src/` (Rust) and `.upstream-v25/src/transactions/` (C++).

---

## Critical Severity

These will cause consensus-breaking divergence on mainnet traffic today.

### C1. No `maxOffersToCross` limit in manage offer

- **Rust:** `manage_offer.rs:842-901` — no crossing limit; will cross all matching offers
- **C++:** `OfferExchange.cpp:1551-1555` — returns `opEXCEEDED_WORK_LIMIT` after 1000 crossings
- **Impact:** Any DEX trade that would cross >1000 offers will succeed in Rust but fail in C++. This changes ledger state (balances, offers removed/modified).
- **Fix:** Add a `max_offers_to_cross` counter (default 1000) in the offer-crossing loop. Return `EXCEEDED_WORK_LIMIT` when reached.

### C2. No liquidity pool exchange in manage offer

- **Rust:** `manage_offer.rs:318-335` — only crosses order book offers
- **C++:** `OfferExchange.cpp:1697-1740` — uses `convertWithOffersAndPools` which considers AMM liquidity pools alongside order book offers for best-price routing
- **Impact:** Any asset pair with a liquidity pool will produce different exchange amounts. Affects every DEX operation on pairs with pools.
- **Fix:** Implement `convertWithOffersAndPools` logic that interleaves pool and order book pricing at each crossing step.

### C3. Missing pool share trustline redemption on authorization revocation

- **Rust:** `trust_flags.rs` — when revoking authorization, only removes offers via `remove_offers_for_revoked_trustline`
- **C++:** `SetTrustLineFlagsOpFrame.cpp` — calls `removeOffersAndPoolShareTrustLines()` which also redeems pool share trustlines and removes the account from liquidity pools
- **Impact:** Revoking authorization on an asset used in a liquidity pool will leave stale pool positions in Rust. Ledger state diverges immediately.
- **Fix:** Implement pool share trustline redemption alongside offer removal when revoking authorization.

### C4. FeeBump operation count off-by-one

- **Rust:** `frame.rs:329-331` — `operation_count()` returns inner transaction's operation count
- **C++:** `FeeBumpTransactionFrame.cpp:567-571` — `getNumOperations()` returns inner op count + 1
- **Impact:** Affects fee-per-operation calculations used in surge pricing, flood control, and resource limits. Every fee bump transaction will have incorrect fee math.
- **Fix:** Return `inner.operation_count() + 1` for fee bump transactions.

### C5. Missing `maybeUpdateAccountOnLedgerSeqUpdate`

- **Rust:** `live_execution.rs` — not called during sequence number processing
- **C++:** `TransactionFrame.cpp:1418` — called to update `seqLedger` and `seqTime` fields on v3 (protocol 19+) account extensions
- **Impact:** Account `seqLedger` and `seqTime` fields will never be set. Any subsequent transaction using `minSeqAge` or `minSeqLedgerGap` preconditions will evaluate against stale values, causing accept/reject divergence.
- **Fix:** After incrementing the sequence number, call the equivalent of `maybeUpdateAccountOnLedgerSeqUpdate` to set `seqLedger = currentLedgerSeq` and `seqTime = currentCloseTime`.

### C6. Fee bump Soroban fee calculation differs

- **Rust:** `live_execution.rs:339-345` — uses `outer_fee` directly as the Soroban resource fee
- **C++:** `FeeBumpTransactionFrame.cpp:524-532` — computes `inner.declaredSorobanResourceFee + min(outer_inclusion_fee, adjusted_fee)` where adjusted_fee accounts for the fee bump spread
- **Impact:** Soroban fee bump transactions will charge different amounts, changing the fee refund and therefore the source account balance. Diverges on every Soroban fee bump.
- **Fix:** Port the C++ fee computation formula that splits inclusion fee from resource fee.

---

## High Severity

These will cause divergence under specific but realistic conditions.

### H1. Missing `finalize_fee_refund` in Soroban fee processing

- **Rust:** `live_execution.rs` — never calls `finalize_fee_refund` after Soroban execution
- **C++:** `TransactionFrame.cpp:977` — calls `finalizeFeeRefund` to adjust `feeCharged` in the result XDR
- **Impact:** Result XDR will show a higher `feeCharged` than C++. While the account balance may still be correct (refund is applied), the result meta will differ, which is consensus-relevant.
- **Fix:** Call `finalize_fee_refund` after Soroban apply to adjust the result's `feeCharged`.

### H2. Fee bump `finalize_fee_refund` logic wrong for protocols 21-24

- **Rust:** `fee_bump.rs:590-602` — only adjusts inner transaction's `feeCharged`
- **C++:** `MutableTransactionResult.cpp:421-443` — adjusts BOTH outer and inner `feeCharged` for protocols 21-24
- **Impact:** Fee bump result XDR differs for all protocols 21-24. The outer result will show the wrong fee.
- **Fix:** When protocol < 25, also set `outerResult.feeCharged = adjustedFee`.

### H3. Ledger bounds off-by-one

- **Rust:** `validation.rs:455` — `current_ledger > max_ledger` (accepts when `current == max`)
- **C++:** `TransactionFrame.cpp:1121-1122` — `max_ledger <= ledgerSeq` (rejects when `current == max`)
- **Impact:** A transaction with `maxLedger == currentLedger` will be accepted by Rust but rejected by C++.
- **Fix:** Change condition to `current_ledger >= max_ledger`.

### H4. Missing min_seq_age / min_seq_ledger_gap checks

- **Rust:** `validation.rs` — error variants `txBAD_MIN_SEQ_AGE_OR_GAP` exist but are never emitted; no code actually checks these preconditions
- **C++:** `TransactionFrame.cpp:1163-1188` — validates `minSeqAge` against `(closeTime - seqTime)` and `minSeqLedgerGap` against `(currentLedger - seqLedger)`
- **Impact:** Transactions that should be rejected for not meeting age/gap preconditions will be accepted.
- **Fix:** Implement the min_seq_age and min_seq_ledger_gap validation using account's seqTime/seqLedger.

### H5. Balance check uses raw balance instead of available balance

- **Rust:** `validation.rs:674` — checks `account.balance >= fee` using raw balance
- **C++:** `TransactionFrame.cpp:1358` — uses `getAvailableBalance()` which subtracts base reserve and selling liabilities
- **Impact:** An account with sufficient raw balance but insufficient available balance (due to reserves/liabilities) will pass fee validation in Rust but fail in C++.
- **Fix:** Use available balance (balance - required_reserves - selling_liabilities) for fee validation.

### H6. Missing Soroban resource limit validation

- **Rust:** `validation.rs` — only checks archived entry indices in Soroban validation
- **C++:** `TransactionFrame.cpp:298-395` — validates instructions, read/write bytes, read/write entry counts, key types, transaction size, duplicate footprint entries, and more
- **Impact:** Invalid Soroban transactions that C++ rejects at validation will be accepted by Rust and proceed to execution, producing different results.
- **Fix:** Port the full `validateSorobanResources` and `validateSorobanOpsConsistency` checks.

### H7. Ed25519SignedPayload signer comparison ignores payload

- **Rust:** `set_options.rs:384-386` — `compare_signer_keys` only compares the ed25519 field of signed payload signers
- **C++:** `SetOptionsOpFrame.cpp` — compares the full `Ed25519SignedPayload` structure including the payload bytes
- **Impact:** Two signers with the same ed25519 key but different payloads will be considered identical in Rust. This affects signer ordering and deduplication in `set_options`.
- **Fix:** Compare the full signed payload structure (ed25519 key + payload bytes).

### H8. Hash-X 32-byte length restriction

- **Rust:** `signature_checker.rs:253` — rejects preimages that are not exactly 32 bytes
- **C++:** `SignatureChecker.cpp` — accepts any-length preimage whose SHA-256 hash matches
- **Impact:** A valid Hash-X signature with a preimage != 32 bytes will be rejected by Rust but accepted by C++. While most preimages are 32 bytes, the protocol does not mandate this.
- **Fix:** Remove the 32-byte length check; accept any preimage and verify `SHA256(preimage) == hash`.

---

## Medium Severity

These cause divergence in edge cases or affect result XDR fidelity.

### M1. Missing `isAssetValid` checks in multiple operations

- **Rust:** `manage_offer.rs`, `change_trust.rs`, `path_payment.rs`, `trust_flags.rs` — no asset structure validation
- **C++:** Each corresponding operation calls `isAssetValid()` in `doCheckValid` to reject malformed asset codes (wrong length, invalid characters, etc.)
- **Impact:** Malformed assets that C++ rejects at validation will proceed to execution in Rust.
- **Fix:** Add `is_asset_valid()` checks in each operation's validation path.

### M2. Missing `TOO_MANY_SPONSORING` result code

- **Rust:** `manage_offer.rs`, `change_trust.rs`, `manage_data.rs`, `claimable_balance.rs`, `sponsorship.rs`, `set_options.rs` — no sponsorship counter overflow check
- **C++:** Returns `TOO_MANY_SPONSORING` when the `numSponsoring` counter would exceed `UINT32_MAX`
- **Impact:** Extremely unlikely on mainnet (requires 4 billion sponsored entries), but Rust would wrap/panic where C++ returns a clean error.
- **Fix:** Add overflow check on `numSponsoring` increment, returning the appropriate `TOO_MANY_SPONSORING` result code.

### M3. Missing home domain validation in set_options

- **Rust:** `set_options.rs` — no validation on the home domain string
- **C++:** `SetOptionsOpFrame.cpp` — calls `isStringValid()` to reject strings with non-printable/control characters
- **Impact:** Home domains with control characters or null bytes will be accepted by Rust but rejected by C++.
- **Fix:** Add string validation rejecting non-printable characters (matching C++'s `isStringValid`).

### M4. Soroban memo validation scope mismatch

- **Rust:** `frame.rs:639-664` — validates memo restrictions for ALL Soroban operation types
- **C++:** `TransactionFrame.cpp:311-340` — only validates memo for `InvokeHostFunction` operations
- **Impact:** A `RestoreFootprint` or `ExtendFootprintTTL` operation with a memo that would be rejected by the receiver's memo-required flag will fail in Rust but succeed in C++.
- **Fix:** Only apply memo validation for `InvokeHostFunction` operations.

### M5. Missing `validateContractLedgerEntry` in extend/restore

- **Rust:** `extend_footprint_ttl.rs`, `restore_footprint.rs` — no entry size validation
- **C++:** `ExtendFootprintTTLOpFrame.cpp`, `RestoreFootprintOpFrame.cpp` — calls `validateContractLedgerEntry()` to check entry size limits
- **Impact:** Oversized contract entries that C++ rejects will be processed by Rust.
- **Fix:** Port `validateContractLedgerEntry` size checks.

### M6. Missing rent fee computation in restore_footprint

- **Rust:** `restore_footprint.rs` — no rent fee calculation
- **C++:** `RestoreFootprintOpFrame.cpp` — computes rent fees via `rust_bridge::compute_rent_fee()` and validates against the fee budget
- **Impact:** Restore operations that exceed their fee budget will succeed in Rust but fail in C++.
- **Fix:** Implement rent fee computation and validation.

### M7. Missing write bytes metering in restore_footprint

- **Rust:** `restore_footprint.rs` — only meters read bytes
- **C++:** `RestoreFootprintOpFrame.cpp` — meters both read bytes and write bytes
- **Impact:** A restore that exceeds write byte limits will succeed in Rust but fail in C++.
- **Fix:** Add write bytes metering for restored entries.

### M8. Signed vs unsigned predicate comparison in ClaimClaimableBalance

- **Rust:** `claimable_balance.rs` — uses signed comparison for `RelBefore` time predicates
- **C++:** `ClaimClaimableBalanceOpFrame.cpp` — uses unsigned comparison
- **Impact:** Diverges near INT64_MAX boundary (close time > 2^63). Extremely unlikely in practice but technically incorrect.
- **Fix:** Use unsigned comparison for time values.

### M9. Missing negative `offer_id` check in manage offer

- **Rust:** `manage_offer.rs` — no check for negative offer IDs in delete/modify path
- **C++:** `ManageOfferOpFrameBase.cpp` — rejects `offerID < 0` with `MALFORMED`
- **Impact:** A manage offer with a negative offer ID will proceed to execution in Rust (likely failing at lookup) rather than being rejected at validation.
- **Fix:** Add `offer_id < 0` check returning `MALFORMED`.

---

## Low Severity

These are unlikely to affect consensus but represent correctness gaps.

### L1. bigDivide overflow handling in liquidity pool

- **Rust:** `liquidity_pool.rs` — returns `0` on overflow
- **C++:** `LiquidityPoolDepositOpFrame.cpp` — returns `false` (distinct from `0`), allowing `minAmongValid` to skip the result
- **Impact:** If overflow produces 0 and 0 is then selected as the minimum, pool deposit/withdraw amounts could differ. Requires extreme token amounts.
- **Fix:** Return `Option<i64>` (None on overflow) instead of 0.

### L2. bigSquareRoot algorithm difference in liquidity pool

- **Rust:** `liquidity_pool.rs` — uses binary search on i128 (signed)
- **C++:** `LiquidityPoolDepositOpFrame.cpp` — uses Newton's method on uint128 (unsigned)
- **Impact:** Both should produce the same result for valid inputs, but edge cases near i128/u128 boundaries could differ. Needs verification with extreme values.
- **Fix:** Verify both algorithms produce identical results for all possible pool token amounts, or port the Newton's method implementation.

### L3. Missing non-positive deposit amount assertion in liquidity pool

- **Rust:** `liquidity_pool.rs` — only warns on negative pool shares
- **C++:** `LiquidityPoolDepositOpFrame.cpp` — throws if `amountA <= 0 || amountB <= 0 || shares <= 0`
- **Impact:** In C++, hitting this assert would halt the node. In Rust, execution continues with invalid values. The path to trigger this is unclear.
- **Fix:** Add assertions (or error returns) matching C++'s invariant checks.

### L4. Missing P23 hot archive corruption bug verifier

- **Rust:** No equivalent of `P23HotArchiveBug` reconciliation
- **C++:** `InvokeHostFunctionOpFrame.cpp` — has special-case handling for a known protocol 23 bug
- **Impact:** Only relevant if replaying protocol 23 ledgers. Not a concern for forward-only protocol 25 execution.
- **Fix:** Implement if historical replay is required; otherwise document as intentional omission.

### L5. Event size checking differs in InvokeHostFunction

- **Rust:** Checks a single pre-computed total event size
- **C++:** Checks incrementally per-event with a separate `return_value` size check
- **Impact:** Could diverge if individual events are within limits but the total exceeds, or vice versa. Depends on exact limit semantics.
- **Fix:** Align event size checking to match the incremental per-event approach.

---

## Structural Differences (Non-Consensus)

These are architectural differences that do not affect observable behavior:

| Aspect | Rust (Henyey) | C++ (stellar-core) |
|--------|---------------|---------------------|
| Architecture | Flat functions, trait-based dispatch | Class hierarchy with virtual methods |
| State management | `LedgerStateManager` with explicit savepoints | Nested `LedgerTxn` with RAII rollback |
| Error handling | `Result<T, E>` propagation | Exceptions + assertions |
| Event emission | Largely missing (scope gap) | Full event emission via `EventManager` |
| Metrics/logging | Minimal | Extensive per-operation metrics |

---

## Scope Gaps (Missing Features)

Features present in C++ but entirely absent in Rust, beyond the behavioral deltas above:

1. **Liquidity pool integration in DEX** — Pools are not considered during offer exchange (covered in C2)
2. **Event emission from classic operations** — C++ emits balance/trustline/offer change events; Rust does not
3. **Full Soroban resource validation** — Multiple validation checks missing (covered in H6)
4. **Historical protocol bug compatibility** — P23 hot archive bug handling not implemented (covered in L4)

---

## Recommended Fix Priority

1. **Immediate (blocks testnet parity):** C1, C2, C3, C4, C5, C6
2. **High priority (blocks correctness):** H1-H8
3. **Medium priority (edge cases):** M1-M9
4. **Low priority (hardening):** L1-L5

---

## Methodology

Each Rust source file in `crates/tx/src/` was compared against its C++ counterpart(s) in `.upstream-v25/src/transactions/` using side-by-side pseudocode generation. The comparison focused on:

- Guard check ordering and conditions
- State mutations and their sequencing
- Decision points and branching logic
- Cross-function calls and their parameters
- Return values and error codes

Excluded from comparison: test code, logging, metrics, memory management, and type conversions (unless containing logic).
