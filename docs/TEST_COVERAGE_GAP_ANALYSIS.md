# stellar-core to Rust Transaction Test Coverage Gap Analysis

Analysis of test coverage gaps between stellar-core v25 and henyey transaction tests.
This document identifies test scenarios present in stellar-core that are missing in the Rust implementation.

## Executive Summary

| Metric | stellar-core (v25) | Rust (henyey) |
|--------|----------------------|----------------------|
| Test Files | 32 | 20 |
| TEST_CASE/SECTION count | ~1,813 | ~181 |
| Estimated Test Scenarios | ~500+ | ~150+ |

**Overall Coverage Gap: Approximately 65-70% of stellar-core test scenarios are NOT covered in Rust tests.**

---

## Critical Missing Tests (Consensus-Breaking Risk)

These are the highest priority gaps that could cause ledger divergence.

### 1. INT64_MAX Overflow Tests

**Risk:** Arithmetic overflow can cause different results between implementations.

Missing scenarios:
- Payment to account with max buying liabilities
- PathPayment through offers causing overflow
- AccountMerge destination reaching INT64_MAX
- Pool share calculation overflow in LiquidityPoolDeposit

**stellar-core References:**
- `PaymentTests.cpp`: "issuer large amounts" section
- `PathPaymentTests.cpp`: overflow sections
- `MergeTests.cpp`: "destination with native buying liabilities"
- `LiquidityPoolDepositTests.cpp`: overflow tests

### 2. Subentries Limit Tests

**Risk:** Missing limit checks cause `OpTooManySubentries` divergence (bug discovered at mainnet ledger 54003784).

Missing scenarios:
- [ ] CreateAccount with sponsor at subentry limit
- [ ] ManageOffer when account has 1000 subentries
- [ ] SetOptions adding signer at subentry limit
- [ ] ManageData creating entry at limit
- [ ] ClaimableBalance creation at limit

**stellar-core References:**
- `SponsorshipTestUtils.cpp`: `tooManySubentries()` helper used across all operations
- `ChangeTrustTests.cpp:282`: `tooManySubentries(*app, acc1, changeTrust(idr, 1), ...)`
- `SetOptionsTests.cpp:334`: `tooManySubentries(*app, a1, setOptions(setSigner(signer1)), ...)`
- `ManageDataTests.cpp:185`: `tooManySubentries(*app, acc1, manageData(t1, &value), ...)`

### 3. Sequence Number Edge Cases

Missing scenarios:
- [ ] `SEQNUM_TOO_FAR` for AccountMerge (v10+)
- [ ] `MAX_SEQ_NUM_TO_APPLY` interactions (v19+)
- [ ] BumpSequence to INT64_MAX
- [ ] BumpSequence with sponsored account

**stellar-core References:**
- `MergeTests.cpp`: "merge too far" and "merge too far due to MAX_SEQ_NUM_TO_APPLY"
- `BumpSequenceTests.cpp`: comprehensive sequence tests

### 4. Multi-Operation Transaction Interactions

**Risk:** State changes from earlier operations affecting later ones.

Missing scenarios:
- [ ] Pay + Merge combinations (source account pays then merges)
- [ ] Create + Merge + Pay sequences
- [ ] Trustline create + delete in same transaction
- [ ] Source account deleted mid-transaction
- [ ] "Two payments, first breaking second" ledger test

**stellar-core References:**
- `PaymentTests.cpp`: Multi-op test sections
- `MergeTests.cpp`: "merge, create, merge back" and similar
- `ChangeTrustTests.cpp:287-303`: "create and delete trustline in same tx"

---

## Per-Operation Coverage Gaps

### CreateAccount

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Basic success | YES | YES | - |
| Account already exists | YES | YES | - |
| Low reserve | YES | YES | - |
| Malformed bad starting balance | YES | NO | **Missing** |
| Malformed destination | YES | NO | **Missing** |
| With native selling liabilities | YES | NO | **Missing** |
| With native buying liabilities | YES | NO | **Missing** |
| With sponsorship | YES | NO | **Missing** |
| Too many sponsoring | YES | NO | **Missing** |

**stellar-core File:** `CreateAccountTests.cpp` (11 test sections)
**Rust File:** `create_account.rs` (3 tests)

### Payment

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Native payment success | YES | YES | - |
| No destination | YES | YES | - |
| Underfunded | YES | YES | - |
| With liabilities | YES | YES | - |
| Rescue account below reserve | YES | NO | **Missing** |
| Two payments first breaking second | YES | NO | **Missing** |
| Issuer large amounts (INT64_MAX) | YES | NO | **Critical** |
| Multi-op pay+merge sequences | YES | NO | **Critical** |
| Credit missing issuer (v13+) | YES | NO | **Missing** |
| Authorize flag interactions | YES | NO | **Missing** |

**stellar-core File:** `PaymentTests.cpp` (78 test sections)
**Rust File:** `payment.rs` (14 tests)

### AccountMerge

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Basic success | YES | YES | - |
| Merge into self (MALFORMED) | YES | YES | - |
| Destination full | YES | YES | - |
| Seqnum too far | YES | YES | - |
| Is sponsor | YES | YES | - |
| Merge into non-existent | YES | NO | **Missing** |
| Multi-op merge+create sequences | YES | NO | **Missing** |
| Merge account twice | YES | NO | **Missing** |
| AUTH_IMMUTABLE_FLAG check | YES | NO | **Missing** |
| With sub-entries (trustline/offer/data) | YES | NO | **Missing** |
| Invalidates dependent tx | YES | NO | **Missing** |
| Reserve boundary edge cases | YES | NO | **Missing** |
| MAX_SEQ_NUM_TO_APPLY (v19+) | YES | NO | **Critical** |
| Destination native buying liab overflow | YES | NO | **Critical** |
| Complex sponsorship scenarios | YES | NO | **Missing** |

**stellar-core File:** `MergeTests.cpp` (48 test sections)
**Rust File:** `account_merge.rs` (5 tests)

### ChangeTrust

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Basic create/update/delete | YES | YES | - |
| Invalid limit | YES | YES | - |
| No issuer | YES | YES | - |
| Self trust | YES | YES | - |
| Low reserve | YES | YES | - |
| Pool share basic | YES | YES | - |
| Too many subentries | YES | YES | Fixed |
| Native selling liabilities | YES | NO | **Missing** |
| Native buying liabilities | YES | NO | **Missing** |
| Cannot reduce below buying liab | YES | NO | **Missing** |
| Too many sponsoring | YES | NO | **Missing** |
| Complex sponsorship | YES | NO | **Missing** |
| Pool share with sponsorship | YES | NO | **Missing** |

**stellar-core File:** `ChangeTrustTests.cpp` (39 test sections)
**Rust File:** `change_trust.rs` (18 tests including new regression tests)

### ManageOffer (Sell + Buy)

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Basic CRUD | YES | YES | - |
| Error conditions | YES | YES | - |
| Some liability tests | YES | YES | - |
| Passive offer behavior | YES | NO | **Missing** |
| Complex crossing scenarios | YES | NO | **Missing** |
| Liabilities edge (LINE_FULL) | YES | NO | **Missing** |
| Price overflow/rounding | YES | NO | **Critical** |
| Sponsorship scenarios | YES | NO | **Missing** |
| Self-trade edge cases | YES | NO | **Missing** |
| Offer at INT64_MAX price | YES | NO | **Critical** |

**stellar-core Files:** `OfferTests.cpp`, `ManageBuyOfferTests.cpp` (180+ test sections)
**Rust File:** `manage_offer.rs` (17 tests)

### PathPayment (Strict Receive + Strict Send)

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Basic success/failure | YES | YES | - |
| Limited error conditions | YES | YES | - |
| INT64_MAX overflow | YES | NO | **Critical** |
| Complex multi-hop paths | YES | NO | **Missing** |
| Loop detection | YES | NO | **Missing** |
| Liabilities interaction | YES | NO | **Missing** |
| Missing issuer scenarios | YES | NO | **Missing** |
| Path through liquidity pool | YES | NO | **Missing** |

**stellar-core Files:** `PathPaymentTests.cpp`, `PathPaymentStrictSendTests.cpp` (185+ test sections)
**Rust File:** `path_payment.rs` (6 tests)

### SetOptions

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Basic flag/threshold/signer | YES | YES | - |
| Home domain tests | YES | YES | - |
| Signer with native liabilities | YES | NO | **Missing** |
| Too many signers limit | YES | NO | **Missing** |
| Complex sponsorship | YES | NO | **Missing** |
| Ed25519 payload signer (v18/v19+) | YES | NO | **Missing** |
| Signer deletion with sponsorship | YES | NO | **Missing** |
| Master key as alternate signer | YES | NO | **Missing** |

**stellar-core File:** `SetOptionsTests.cpp` (22 test sections)
**Rust File:** `set_options.rs` (15 tests)

### ClaimableBalance

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Basic create/claim | YES | YES | - |
| Predicate tests | YES | YES | - |
| Some error conditions | YES | YES | - |
| Complex predicate combos (AND/OR/NOT) | YES | NO | **Missing** |
| Time-based predicate edge cases | YES | NO | **Missing** |
| Sponsorship transfer | YES | NO | **Missing** |
| Claimant limit tests | YES | NO | **Missing** |
| Reserve calculation edge cases | YES | NO | **Missing** |

**stellar-core File:** `ClaimableBalanceTests.cpp` (73 test sections)
**Rust File:** `claimable_balance.rs` (18 tests)

### Liquidity Pool Operations

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Basic deposit/withdraw | YES | YES | - |
| Pool share calculation overflow | YES | NO | **Critical** |
| Trading through pools | YES | NO | **Missing** |
| Authorization edge cases | YES | NO | **Missing** |
| Pool full scenarios | YES | NO | **Missing** |
| Price bounds validation | YES | NO | **Missing** |

**stellar-core Files:** `LiquidityPoolDepositTests.cpp`, `LiquidityPoolWithdrawTests.cpp`, `LiquidityPoolTradeTests.cpp` (88+ test sections)
**Rust File:** `liquidity_pool.rs` (7 tests)

### Sponsorship Operations

| Test Scenario | stellar-core | Rust | Gap |
|---------------|-----|------|-----|
| Basic begin/end sponsoring | YES | YES | - |
| Some revoke scenarios | YES | YES | - |
| Complex transfer scenarios | YES | NO | **Missing** |
| Entry-specific sponsorship | YES | NO | **Missing** |
| Low reserve edge cases | YES | NO | **Missing** |
| Nested sponsorship | YES | NO | **Missing** |

**stellar-core Files:** `RevokeSponsorshipTests.cpp`, `BeginSponsoringFutureReservesTests.cpp`, etc. (66+ test sections)
**Rust File:** `sponsorship.rs` (11 tests)

### Other Operations Summary

| Operation | stellar-core Depth | Rust Depth | Gap Level |
|-----------|-----------|------------|-----------|
| BumpSequence | 12 sections | 3 tests | Medium |
| ManageData | 5 sections | 12 tests | OK |
| Inflation | 18 sections | 1 test | Large |
| Clawback | 19 sections | 3 tests | Large |
| SetTrustLineFlags | 72 sections | 7 tests | Large |
| AllowTrust | 56 sections | 7 tests | Large |
| InvokeHostFunction | 371 sections | 18 tests | Large (Soroban) |

---

## Prioritized Remediation Plan

### Tier 1: Critical (Consensus Breaking Risk)

These tests should be added immediately as they test scenarios that could cause ledger divergence:

1. **INT64_MAX Overflow Tests** for:
   - Payment to account with max buying liabilities
   - PathPayment through offers
   - AccountMerge destination full
   - Pool share calculation

2. **Subentries Limit Tests** for all operations:
   - Already fixed for ChangeTrust
   - Need to add for: CreateAccount, ManageOffer, SetOptions, ManageData, ClaimableBalance

3. **Multi-Operation Transaction Tests**:
   - Pay + Merge combinations
   - Create + Merge sequences
   - Source account state changes affecting later operations

### Tier 2: High Priority (Operation Parity)

4. **Sponsorship Complex Scenarios**:
   - Too many sponsoring
   - Sponsorship transfer
   - Entry deletion with sponsorship

5. **Protocol Version-Specific Tests**:
   - v10+ liability changes
   - v14+ sponsorship
   - v17+ clawback
   - v18+ liquidity pools
   - v19+ preconditions and MAX_SEQ_NUM_TO_APPLY

6. **Complete Error Code Coverage**:
   - Each operation should test ALL possible result codes

### Tier 3: Medium Priority (Edge Cases)

7. **Reserve Boundary Tests**:
   - Account with exactly base reserve
   - Account with base reserve + fee - 1 stroop

8. **Self-Operation Tests**:
   - Self payment edge cases
   - Self path payment through loops

9. **Issuer Operation Tests**:
   - Issuer paying to/from trustlines
   - Issuer with large amounts

---

## Test Infrastructure Gaps

Beyond individual test cases, the Rust test infrastructure lacks some patterns from stellar-core:

1. **No equivalent to `for_versions_from(N, app, [&] { ... })`** - Many stellar-core tests run across multiple protocol versions

2. **No `SponsorshipTestUtils` equivalent** - stellar-core has reusable helpers like `tooManySubentries()`, `tooManySponsoring()`

3. **No ledger-level transaction tests** - stellar-core tests transactions at the ledger level, verifying dependent transaction invalidation

4. **Limited multi-operation transaction testing** - Most Rust tests are single-operation

---

## References

### stellar-core Test Files

```
.upstream-v25/src/transactions/test/
├── CreateAccountTests.cpp
├── PaymentTests.cpp
├── MergeTests.cpp
├── ChangeTrustTests.cpp
├── OfferTests.cpp
├── ManageBuyOfferTests.cpp
├── PathPaymentTests.cpp
├── PathPaymentStrictSendTests.cpp
├── SetOptionsTests.cpp
├── BumpSequenceTests.cpp
├── ManageDataTests.cpp
├── ClaimableBalanceTests.cpp
├── LiquidityPoolDepositTests.cpp
├── LiquidityPoolWithdrawTests.cpp
├── LiquidityPoolTradeTests.cpp
├── RevokeSponsorshipTests.cpp
├── BeginSponsoringFutureReservesTests.cpp
├── ClawbackTests.cpp
├── ClawbackClaimableBalanceTests.cpp
├── SetTrustLineFlagsTests.cpp
├── AllowTrustTests.cpp
├── InflationTests.cpp
├── InvokeHostFunctionTests.cpp
├── ExtendFootprintTtlTests.cpp
├── RestoreFootprintTests.cpp
├── SponsorshipTestUtils.cpp
└── TxEnvelopeTests.cpp
```

### Rust Test Files

```
crates/henyey-tx/src/operations/execute/
├── create_account.rs (3 tests)
├── payment.rs (14 tests)
├── account_merge.rs (5 tests)
├── change_trust.rs (18 tests)
├── manage_offer.rs (17 tests)
├── path_payment.rs (6 tests)
├── set_options.rs (15 tests)
├── claimable_balance.rs (18 tests)
├── sponsorship.rs (11 tests)
└── liquidity_pool.rs (7 tests)
```
