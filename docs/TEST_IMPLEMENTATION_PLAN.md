# Test Implementation Plan

Comprehensive plan to achieve full test parity with C++ stellar-core v25 transaction tests.

## Overview

**Goal:** Implement ~350 missing test scenarios to close the 65-70% coverage gap.

**Timeline Estimate:** 4-6 weeks of focused effort (or can be parallelized across contributors)

**Priority Order:**
1. Test infrastructure (enables all other tests)
2. Critical consensus tests (INT64_MAX, subentries, multi-op)
3. Per-operation complete coverage
4. Protocol version-specific tests

---

## Phase 0: Test Infrastructure (Week 1)

Before implementing individual tests, build reusable test infrastructure matching C++ patterns.

### Task 0.1: Create Test Utilities Module

**File:** `crates/stellar-core-tx/src/test_utils.rs`

```rust
//! Shared test utilities for transaction tests.
//!
//! Mirrors C++ SponsorshipTestUtils and TestUtils patterns.

/// Maximum account subentries (matches C++ ACCOUNT_SUBENTRY_LIMIT)
pub const ACCOUNT_SUBENTRY_LIMIT: u32 = 1000;

/// Create a test account with specified balance and subentries
pub fn create_test_account_with_subentries(
    id: AccountId,
    balance: i64,
    num_sub_entries: u32,
) -> AccountEntry { ... }

/// Create a test account at the subentry limit
pub fn create_account_at_subentry_limit(id: AccountId, balance: i64) -> AccountEntry {
    create_test_account_with_subentries(id, balance, ACCOUNT_SUBENTRY_LIMIT)
}

/// Create a test account one below subentry limit
pub fn create_account_near_subentry_limit(id: AccountId, balance: i64) -> AccountEntry {
    create_test_account_with_subentries(id, balance, ACCOUNT_SUBENTRY_LIMIT - 1)
}
```

### Task 0.2: Create Sponsorship Test Helpers

**File:** `crates/stellar-core-tx/src/test_utils/sponsorship.rs`

```rust
//! Sponsorship test helpers matching C++ SponsorshipTestUtils.cpp

/// Test that an operation fails with OpTooManySubentries when account is at limit.
///
/// Pattern: Set account to limit, run operation, expect OpTooManySubentries.
///
/// # Arguments
/// * `state` - Ledger state manager
/// * `account` - Account to test (will be set to subentry limit)
/// * `operation` - Operation that creates a subentry
/// * `multiplier` - Number of subentries the operation creates (1 for most, 2 for pool share)
pub fn test_too_many_subentries<F>(
    state: &mut LedgerStateManager,
    account: &AccountId,
    operation: F,
    multiplier: u32,
) where
    F: FnOnce(&mut LedgerStateManager) -> Result<OperationResult>,
{ ... }

/// Test that an operation fails with OpTooManySponsoring.
pub fn test_too_many_sponsoring<F>(...) { ... }

/// Set up a sponsored entry for testing.
pub fn setup_sponsored_entry(
    state: &mut LedgerStateManager,
    sponsor: &AccountId,
    sponsored: &AccountId,
    entry_key: &LedgerKey,
) { ... }
```

### Task 0.3: Create Multi-Operation Transaction Test Framework

**File:** `crates/stellar-core-tx/src/test_utils/multi_op.rs`

```rust
//! Multi-operation transaction test framework.

/// Execute multiple operations in sequence, tracking state between each.
pub struct MultiOpTestRunner {
    state: LedgerStateManager,
    context: LedgerContext,
    results: Vec<OperationResult>,
}

impl MultiOpTestRunner {
    pub fn new(base_reserve: i64, base_fee: u32) -> Self { ... }

    /// Execute an operation and record result
    pub fn execute<F>(&mut self, op: F) -> &OperationResult
    where F: FnOnce(&mut LedgerStateManager, &LedgerContext) -> Result<OperationResult>
    { ... }

    /// Assert the last operation succeeded
    pub fn assert_success(&self) { ... }

    /// Assert the last operation failed with specific code
    pub fn assert_failed(&self, expected: impl Into<OperationResult>) { ... }
}
```

### Task 0.4: Create INT64_MAX Test Helpers

**File:** `crates/stellar-core-tx/src/test_utils/overflow.rs`

```rust
//! Overflow and boundary test helpers.

pub const MAX_INT64: i64 = i64::MAX;
pub const NEAR_MAX_INT64: i64 = i64::MAX - 1_000_000;

/// Create account with balance near INT64_MAX
pub fn create_account_near_max_balance(id: AccountId) -> AccountEntry { ... }

/// Create trustline with balance near INT64_MAX
pub fn create_trustline_near_max_balance(...) -> TrustLineEntry { ... }

/// Create account with max buying liabilities
pub fn create_account_with_max_buying_liabilities(...) -> AccountEntry { ... }
```

### Task 0.5: Protocol Version Test Macro

**File:** `crates/stellar-core-tx/src/test_utils/versioned.rs`

```rust
//! Protocol version-aware test helpers.

/// Run a test across multiple protocol versions.
///
/// Equivalent to C++ `for_versions_from(N, app, [&] { ... })`
#[macro_export]
macro_rules! for_protocol_versions_from {
    ($min_version:expr, $test_body:expr) => {
        for version in $min_version..=CURRENT_PROTOCOL_VERSION {
            let context = LedgerContext::with_protocol_version(version);
            $test_body(version, context);
        }
    };
}

/// Run a test only for specific protocol version range
#[macro_export]
macro_rules! for_protocol_versions {
    ($min:expr, $max:expr, $test_body:expr) => { ... };
}
```

---

## Phase 1: Critical Consensus Tests (Week 1-2)

These tests prevent consensus-breaking bugs like the ChangeTrust issue.

### Task 1.1: Subentries Limit Tests for All Operations

**Files to modify:** Each operation's test module

| Operation | File | Test Name | Multiplier |
|-----------|------|-----------|------------|
| CreateAccount | `create_account.rs` | `test_create_account_too_many_subentries` | 1 |
| ChangeTrust | `change_trust.rs` | Already done | 1 or 2 |
| ManageSellOffer | `manage_offer.rs` | `test_manage_sell_offer_too_many_subentries` | 1 |
| ManageBuyOffer | `manage_offer.rs` | `test_manage_buy_offer_too_many_subentries` | 1 |
| CreatePassiveSellOffer | `manage_offer.rs` | `test_passive_offer_too_many_subentries` | 1 |
| SetOptions (signer) | `set_options.rs` | `test_set_options_signer_too_many_subentries` | 1 |
| ManageData | `manage_data.rs` | `test_manage_data_too_many_subentries` | 1 |
| CreateClaimableBalance | `claimable_balance.rs` | `test_create_claimable_balance_too_many_subentries` | 1 |

**Implementation pattern:**
```rust
#[test]
fn test_<operation>_too_many_subentries() {
    let mut state = LedgerStateManager::new(5_000_000, 100);
    let context = create_test_context();

    let source_id = create_test_account_id(0);
    let mut source = create_test_account(source_id.clone(), 1_000_000_000);
    source.num_sub_entries = ACCOUNT_SUBENTRY_LIMIT; // At the limit
    state.create_account(source);

    // ... set up operation-specific state ...

    let result = execute_<operation>(&op, &source_id, &mut state, &context);
    assert!(matches!(result.unwrap(), OperationResult::OpTooManySubentries));
}
```

### Task 1.2: INT64_MAX Overflow Tests

**File:** `crates/stellar-core-tx/src/operations/execute/overflow_tests.rs` (new)

```rust
//! INT64_MAX overflow tests for all operations.

mod payment_overflow {
    #[test]
    fn test_payment_overflow_destination_balance() {
        // Destination has balance near MAX, payment would overflow
    }

    #[test]
    fn test_payment_overflow_with_buying_liabilities() {
        // Destination has max buying liabilities
    }
}

mod path_payment_overflow {
    #[test]
    fn test_path_payment_overflow_through_offers() {
        // Path payment causes offer exchange overflow
    }

    #[test]
    fn test_path_payment_strict_send_overflow() {
        // destMin calculation overflow
    }
}

mod account_merge_overflow {
    #[test]
    fn test_merge_overflow_destination_balance() {
        // Merge would cause destination balance overflow
    }

    #[test]
    fn test_merge_overflow_with_buying_liabilities() {
        // Destination has native buying liabilities near max
    }
}

mod liquidity_pool_overflow {
    #[test]
    fn test_pool_deposit_share_calculation_overflow() {
        // Pool share calculation would overflow
    }

    #[test]
    fn test_pool_withdraw_amount_overflow() {
        // Withdrawal amount calculation overflow
    }
}

mod offer_overflow {
    #[test]
    fn test_offer_price_overflow() {
        // Offer with extreme price causing overflow
    }

    #[test]
    fn test_offer_crossing_overflow() {
        // Crossing offers causes balance overflow
    }
}
```

### Task 1.3: Multi-Operation Transaction Tests

**File:** `crates/stellar-core-tx/tests/multi_op_transactions.rs` (new integration test)

```rust
//! Multi-operation transaction integration tests.
//!
//! Tests state changes across operations within a single transaction.

#[test]
fn test_pay_then_merge_source() {
    // Source pays to dest, then merges into dest
    // Verifies source balance updates correctly between ops
}

#[test]
fn test_create_merge_pay_sequence() {
    // Create account, merge it back, pay from original
}

#[test]
fn test_trustline_create_delete_same_tx() {
    // Create trustline then delete it in same transaction
}

#[test]
fn test_source_account_modified_mid_tx() {
    // Multiple operations modify source account
    // Each operation sees updated state
}

#[test]
fn test_two_payments_first_breaks_second() {
    // First payment leaves insufficient balance for second
}

#[test]
fn test_offer_created_and_crossed_same_tx() {
    // Create offer, then another op crosses it
}

#[test]
fn test_merge_then_create_same_account() {
    // Merge account, then create it again in same tx
}

#[test]
fn test_sponsor_and_use_sponsorship_same_tx() {
    // Begin sponsoring, create sponsored entry, end sponsoring
}
```

### Task 1.4: Sequence Number Edge Cases

**File:** `crates/stellar-core-tx/src/operations/execute/account_merge.rs`

```rust
#[test]
fn test_merge_seqnum_too_far_basic() {
    // Already exists - verify it works
}

#[test]
fn test_merge_seqnum_at_max_seq_num_to_apply() {
    // v19+: MAX_SEQ_NUM_TO_APPLY check
    // seqNum > destination.seqNum + MAX_SEQ_NUM_TO_APPLY
}

#[test]
fn test_merge_seqnum_exactly_at_limit() {
    // Boundary case: exactly at the limit (should succeed)
}

#[test]
fn test_merge_seqnum_one_over_limit() {
    // Boundary case: one over limit (should fail)
}
```

**File:** `crates/stellar-core-tx/src/operations/execute/bump_sequence.rs`

```rust
#[test]
fn test_bump_to_int64_max() {
    // Bump sequence to INT64_MAX
}

#[test]
fn test_bump_over_int64_max() {
    // Attempt to bump beyond INT64_MAX
}

#[test]
fn test_bump_with_sponsorship() {
    // Bump sequence on sponsored account
}
```

---

## Phase 2: CreateAccount Complete Coverage (Week 2)

**C++ Reference:** `CreateAccountTests.cpp` (11 test sections)

### Task 2.1: Existing Tests (verify)
- [x] `test_create_account_success`
- [x] `test_create_account_already_exists`
- [x] `test_create_account_low_reserve`

### Task 2.2: Missing Tests

```rust
#[test]
fn test_create_account_malformed_negative_balance() {
    // Starting balance < 0
}

#[test]
fn test_create_account_malformed_zero_balance_pre_v14() {
    // Starting balance == 0 before protocol 14
}

#[test]
fn test_create_account_malformed_destination_is_source() {
    // Destination == source account
}

#[test]
fn test_create_account_with_native_selling_liabilities() {
    // Source has native selling liabilities
    // Available balance = balance - sellingLiabilities
    // Must have available >= startingBalance + reserve
}

#[test]
fn test_create_account_with_native_buying_liabilities() {
    // Source has native buying liabilities
    // Doesn't affect create account (only selling matters)
}

#[test]
fn test_create_account_with_sponsorship() {
    // Create account with active sponsorship
    // Sponsor pays reserve instead of creator
}

#[test]
fn test_create_account_too_many_sponsoring() {
    // Sponsor has too many sponsored entries
}

#[test]
fn test_create_account_too_many_subentries() {
    // Task 1.1 covers this
}
```

---

## Phase 3: Payment Complete Coverage (Week 2)

**C++ Reference:** `PaymentTests.cpp` (78 test sections)

### Task 3.1: Existing Tests (verify)
- [x] `test_native_payment_success`
- [x] `test_payment_no_destination`
- [x] `test_payment_underfunded`
- [x] `test_payment_underfunded_with_liabilities`
- [x] `test_payment_malformed`
- [x] Various credit payment tests

### Task 3.2: Missing Tests

```rust
// Native payment edge cases
#[test]
fn test_payment_rescue_account_below_reserve() {
    // Destination has balance below reserve
    // Payment brings it back above reserve
}

#[test]
fn test_payment_to_self_native() {
    // Pay self with native (should succeed, no-op)
}

#[test]
fn test_payment_source_only_has_reserve() {
    // Source has exactly base reserve
    // Any payment should fail (need reserve + fee)
}

#[test]
fn test_payment_with_selling_liabilities() {
    // Source has selling liabilities reducing available balance
}

// Credit payment edge cases
#[test]
fn test_credit_payment_issuer_to_holder() {
    // Issuer pays to trustline holder
    // Issuer balance doesn't change (infinite supply)
}

#[test]
fn test_credit_payment_holder_to_issuer() {
    // Trustline holder pays to issuer
    // Reduces holder balance, issuer balance unchanged
}

#[test]
fn test_credit_payment_issuer_large_amount() {
    // Issuer pays INT64_MAX to holder
}

#[test]
fn test_credit_payment_missing_issuer_v13_plus() {
    // v13+: issuer account doesn't exist
    // Should return NO_ISSUER
}

#[test]
fn test_credit_payment_not_authorized() {
    // Trustline exists but not authorized
}

#[test]
fn test_credit_payment_line_full() {
    // Payment would exceed trustline limit
}

#[test]
fn test_credit_payment_with_buying_liabilities() {
    // Destination has buying liabilities
    // limit - balance - buyingLiabilities
}

#[test]
fn test_credit_payment_self_more_than_have() {
    // Pay self more than balance (edge case)
}

// Multi-op sequences (also in Phase 1)
#[test]
fn test_payment_then_merge_source() { }

#[test]
fn test_two_payments_first_underfunds_second() { }
```

---

## Phase 4: AccountMerge Complete Coverage (Week 2-3)

**C++ Reference:** `MergeTests.cpp` (48 test sections)

### Task 4.1: Existing Tests (verify)
- [x] `test_account_merge_success`
- [x] `test_account_merge_malformed_self`
- [x] `test_account_merge_dest_full`
- [x] `test_account_merge_seqnum_too_far`
- [x] `test_account_merge_is_sponsor`

### Task 4.2: Missing Tests

```rust
#[test]
fn test_merge_no_destination() {
    // Destination account doesn't exist
}

#[test]
fn test_merge_has_trustlines() {
    // Source has non-zero trustline balance
}

#[test]
fn test_merge_has_offers() {
    // Source has open offers
}

#[test]
fn test_merge_has_data_entries() {
    // Source has data entries
}

#[test]
fn test_merge_has_signers() {
    // Source has additional signers
}

#[test]
fn test_merge_auth_immutable_flag() {
    // Source has AUTH_IMMUTABLE_FLAG set
}

#[test]
fn test_merge_invalidates_dependent_tx() {
    // Ledger test: merge source, then try to use source in next tx
}

#[test]
fn test_merge_twice_same_tx() {
    // Merge account, then merge again (second should fail)
}

#[test]
fn test_merge_create_merge_back() {
    // Merge A into B, create A again, merge A into B again
}

#[test]
fn test_merge_with_destination_buying_liabilities() {
    // Destination has native buying liabilities
    // Check overflow: dest.balance + source.balance + dest.buyingLiabilities
}

#[test]
fn test_merge_reserve_boundary_exact() {
    // Source has exactly the reserve (no extra balance)
}

#[test]
fn test_merge_max_seq_num_to_apply_v19() {
    // v19+: check MAX_SEQ_NUM_TO_APPLY limit
}

// Sponsorship scenarios
#[test]
fn test_merge_source_is_sponsoring() {
    // Source is sponsoring other entries - can't merge
}

#[test]
fn test_merge_source_is_sponsored() {
    // Source account itself is sponsored
}

#[test]
fn test_merge_transfer_sponsorship_to_destination() {
    // What happens to entries sponsored by source?
}
```

---

## Phase 5: ChangeTrust Complete Coverage (Week 3)

**C++ Reference:** `ChangeTrustTests.cpp` (39 test sections)

### Task 5.1: Existing Tests (verify)
- [x] Basic create/update/delete
- [x] Invalid limit tests
- [x] No issuer tests
- [x] Self trust tests
- [x] Low reserve tests
- [x] Pool share basic
- [x] Too many subentries (fixed)

### Task 5.2: Missing Tests

```rust
#[test]
fn test_change_trust_with_native_selling_liabilities() {
    // Source has native selling liabilities
    // Affects available balance for reserve
}

#[test]
fn test_change_trust_with_native_buying_liabilities() {
    // Source has native buying liabilities
}

#[test]
fn test_change_trust_reduce_below_buying_liabilities() {
    // Try to reduce limit below balance + buyingLiabilities
}

#[test]
fn test_change_trust_delete_with_buying_liabilities() {
    // Try to delete trustline that has buying liabilities
}

#[test]
fn test_change_trust_too_many_sponsoring() {
    // Sponsor has too many sponsored entries
}

#[test]
fn test_change_trust_with_sponsorship_low_reserve() {
    // Sponsor doesn't have enough reserve
}

#[test]
fn test_change_trust_pool_share_with_sponsorship() {
    // Pool share trustline (2 subentries) with sponsorship
}

#[test]
fn test_change_trust_cannot_delete_pool_share_in_use() {
    // Pool share trustline has liquidity deposited
}

#[test]
fn test_change_trust_version_specific_self_trust() {
    // Self-trust behavior changes across protocol versions
}
```

---

## Phase 6: ManageOffer Complete Coverage (Week 3)

**C++ Reference:** `OfferTests.cpp`, `ManageBuyOfferTests.cpp` (180+ test sections)

### Task 6.1: Organize by Sub-Operation

Create separate test modules:
- `manage_sell_offer_tests.rs`
- `manage_buy_offer_tests.rs`
- `create_passive_offer_tests.rs`
- `offer_crossing_tests.rs`

### Task 6.2: Missing Tests

```rust
// Error conditions
#[test]
fn test_offer_malformed_negative_amount() { }

#[test]
fn test_offer_malformed_zero_price() { }

#[test]
fn test_offer_malformed_invalid_price() { }

#[test]
fn test_offer_sell_no_trust() { }

#[test]
fn test_offer_buy_no_trust() { }

#[test]
fn test_offer_sell_not_authorized() { }

#[test]
fn test_offer_buy_not_authorized() { }

#[test]
fn test_offer_sell_no_issuer() { }

#[test]
fn test_offer_underfunded() { }

#[test]
fn test_offer_line_full() { }

#[test]
fn test_offer_cross_self() { }

// Passive offers
#[test]
fn test_passive_offer_basic() { }

#[test]
fn test_passive_offer_doesnt_cross_equal_price() { }

#[test]
fn test_passive_offer_crosses_better_price() { }

// Crossing scenarios
#[test]
fn test_offer_partial_cross() { }

#[test]
fn test_offer_full_cross() { }

#[test]
fn test_offer_multiple_crosses() { }

#[test]
fn test_offer_cross_with_rounding() { }

// Liabilities
#[test]
fn test_offer_creates_selling_liabilities() { }

#[test]
fn test_offer_creates_buying_liabilities() { }

#[test]
fn test_offer_update_adjusts_liabilities() { }

#[test]
fn test_offer_cancel_releases_liabilities() { }

// Price edge cases
#[test]
fn test_offer_price_overflow() { }

#[test]
fn test_offer_amount_times_price_overflow() { }

// Sponsorship
#[test]
fn test_offer_with_sponsorship() { }

#[test]
fn test_offer_too_many_sponsoring() { }

#[test]
fn test_offer_too_many_subentries() { }
```

---

## Phase 7: PathPayment Complete Coverage (Week 3-4)

**C++ Reference:** `PathPaymentTests.cpp`, `PathPaymentStrictSendTests.cpp` (185+ test sections)

### Task 7.1: Organize by Variant

- `path_payment_strict_receive_tests.rs`
- `path_payment_strict_send_tests.rs`

### Task 7.2: Missing Tests

```rust
// Malformed inputs
#[test]
fn test_path_malformed_negative_amount() { }

#[test]
fn test_path_malformed_send_max_zero() { }

#[test]
fn test_path_malformed_dest_min_zero() { }

#[test]
fn test_path_malformed_invalid_asset() { }

// Path scenarios
#[test]
fn test_path_direct_no_path() { }

#[test]
fn test_path_single_hop() { }

#[test]
fn test_path_multi_hop() { }

#[test]
fn test_path_through_offers() { }

#[test]
fn test_path_through_liquidity_pool() { }

#[test]
fn test_path_mixed_offers_and_pools() { }

// Error conditions
#[test]
fn test_path_no_destination() { }

#[test]
fn test_path_no_trust_destination() { }

#[test]
fn test_path_not_authorized() { }

#[test]
fn test_path_src_no_trust() { }

#[test]
fn test_path_offer_cross_self() { }

#[test]
fn test_path_too_few_offers() { }

#[test]
fn test_path_line_full() { }

#[test]
fn test_path_underfunded() { }

// Overflow scenarios
#[test]
fn test_path_send_amount_overflow() { }

#[test]
fn test_path_receive_amount_overflow() { }

#[test]
fn test_path_intermediate_overflow() { }

// Loop detection
#[test]
fn test_path_simple_loop() { }

#[test]
fn test_path_complex_loop() { }

// Self payment
#[test]
fn test_path_self_native_to_native() { }

#[test]
fn test_path_self_credit_to_credit() { }

#[test]
fn test_path_self_with_path() { }
```

---

## Phase 8: SetOptions Complete Coverage (Week 4)

**C++ Reference:** `SetOptionsTests.cpp` (22 test sections)

### Task 8.1: Missing Tests

```rust
// Signer tests
#[test]
fn test_set_options_signer_insufficient_balance() { }

#[test]
fn test_set_options_signer_with_liabilities() { }

#[test]
fn test_set_options_signer_invalid_weight() { }

#[test]
fn test_set_options_master_key_as_signer() {
    // Can't use master key as alternate signer
}

#[test]
fn test_set_options_too_many_signers() {
    // MAX_SIGNERS = 20
}

#[test]
fn test_set_options_signer_with_sponsorship() { }

#[test]
fn test_set_options_delete_signer_with_sponsorship() { }

#[test]
fn test_set_options_ed25519_payload_signer_v18() { }

#[test]
fn test_set_options_ed25519_payload_signer_v19() { }

// Threshold tests
#[test]
fn test_set_options_bad_thresholds() {
    // e.g., high < medium or medium < low
}

#[test]
fn test_set_options_thresholds_lock_out() {
    // Setting thresholds that would lock out all signers
}

// Flag tests
#[test]
fn test_set_options_auth_required_flag() { }

#[test]
fn test_set_options_auth_revocable_flag() { }

#[test]
fn test_set_options_auth_immutable_flag() { }

#[test]
fn test_set_options_auth_clawback_flag() { }

#[test]
fn test_set_options_cannot_clear_immutable() { }

// Home domain
#[test]
fn test_set_options_home_domain_valid() { }

#[test]
fn test_set_options_home_domain_too_long() { }

#[test]
fn test_set_options_home_domain_invalid_chars() { }
```

---

## Phase 9: ClaimableBalance Complete Coverage (Week 4)

**C++ Reference:** `ClaimableBalanceTests.cpp` (73 test sections)

### Task 9.1: Missing Tests

```rust
// Predicate combinations
#[test]
fn test_claimable_predicate_and_nested() { }

#[test]
fn test_claimable_predicate_or_nested() { }

#[test]
fn test_claimable_predicate_not_nested() { }

#[test]
fn test_claimable_predicate_deeply_nested() {
    // AND(OR(NOT(A), B), C)
}

// Time-based predicates
#[test]
fn test_claimable_before_time_boundary() { }

#[test]
fn test_claimable_after_time_boundary() { }

#[test]
fn test_claimable_time_range() { }

// Multiple claimants
#[test]
fn test_claimable_multiple_claimants() { }

#[test]
fn test_claimable_max_claimants() { }

#[test]
fn test_claimable_duplicate_claimant() { }

// Sponsorship
#[test]
fn test_claimable_with_sponsorship() { }

#[test]
fn test_claimable_claim_releases_sponsorship() { }

#[test]
fn test_claimable_sponsor_transfer() { }

// Reserve calculations
#[test]
fn test_claimable_reserve_for_claimants() { }

#[test]
fn test_claimable_reserve_returned_on_claim() { }

// Claim scenarios
#[test]
fn test_claim_not_claimant() { }

#[test]
fn test_claim_predicate_not_satisfied() { }

#[test]
fn test_claim_balance_already_claimed() { }

#[test]
fn test_claim_destination_line_full() { }
```

---

## Phase 10: Liquidity Pool Complete Coverage (Week 4-5)

**C++ Reference:** `LiquidityPoolDepositTests.cpp`, `LiquidityPoolWithdrawTests.cpp`, `LiquidityPoolTradeTests.cpp` (88+ test sections)

### Task 10.1: Deposit Tests

```rust
#[test]
fn test_deposit_empty_pool() { }

#[test]
fn test_deposit_non_empty_pool() { }

#[test]
fn test_deposit_share_calculation_basic() { }

#[test]
fn test_deposit_share_calculation_overflow() { }

#[test]
fn test_deposit_min_amounts_not_met() { }

#[test]
fn test_deposit_no_trust_asset_a() { }

#[test]
fn test_deposit_no_trust_asset_b() { }

#[test]
fn test_deposit_not_authorized() { }

#[test]
fn test_deposit_underfunded() { }

#[test]
fn test_deposit_pool_full() { }
```

### Task 10.2: Withdraw Tests

```rust
#[test]
fn test_withdraw_basic() { }

#[test]
fn test_withdraw_full_position() { }

#[test]
fn test_withdraw_partial() { }

#[test]
fn test_withdraw_min_amounts_not_met() { }

#[test]
fn test_withdraw_line_full() { }

#[test]
fn test_withdraw_under_minimum() { }
```

### Task 10.3: Trading Tests

```rust
#[test]
fn test_trade_through_pool() { }

#[test]
fn test_trade_pool_vs_offers() { }

#[test]
fn test_trade_pool_slippage() { }

#[test]
fn test_trade_pool_fee() { }
```

---

## Phase 11: Sponsorship Operations Complete Coverage (Week 5)

**C++ Reference:** `RevokeSponsorshipTests.cpp`, `BeginSponsoringFutureReservesTests.cpp` (66+ test sections)

### Task 11.1: Begin/End Sponsoring

```rust
#[test]
fn test_begin_sponsoring_basic() { }

#[test]
fn test_begin_sponsoring_nested() { }

#[test]
fn test_begin_sponsoring_without_end() { }

#[test]
fn test_end_sponsoring_no_begin() { }

#[test]
fn test_sponsorship_across_operations() { }
```

### Task 11.2: Revoke Sponsorship

```rust
#[test]
fn test_revoke_account_sponsorship() { }

#[test]
fn test_revoke_trustline_sponsorship() { }

#[test]
fn test_revoke_offer_sponsorship() { }

#[test]
fn test_revoke_data_sponsorship() { }

#[test]
fn test_revoke_claimable_balance_sponsorship() { }

#[test]
fn test_revoke_signer_sponsorship() { }

#[test]
fn test_revoke_not_sponsor() { }

#[test]
fn test_revoke_low_reserve() { }

#[test]
fn test_revoke_transfer_sponsorship() { }
```

---

## Phase 12: Remaining Operations (Week 5-6)

### Task 12.1: Clawback Tests

```rust
#[test]
fn test_clawback_basic() { }

#[test]
fn test_clawback_not_enabled() { }

#[test]
fn test_clawback_not_issuer() { }

#[test]
fn test_clawback_no_trust() { }

#[test]
fn test_clawback_underfunded() { }

#[test]
fn test_clawback_with_liabilities() { }

#[test]
fn test_clawback_claimable_balance() { }
```

### Task 12.2: SetTrustLineFlags Tests

```rust
#[test]
fn test_set_trust_flags_authorize() { }

#[test]
fn test_set_trust_flags_deauthorize() { }

#[test]
fn test_set_trust_flags_maintain_liabilities() { }

#[test]
fn test_set_trust_flags_clawback() { }

#[test]
fn test_set_trust_flags_pool_revocation() { }

#[test]
fn test_set_trust_flags_not_issuer() { }
```

### Task 12.3: AllowTrust Tests (deprecated but needed for parity)

```rust
#[test]
fn test_allow_trust_authorize() { }

#[test]
fn test_allow_trust_deauthorize() { }

#[test]
fn test_allow_trust_not_issuer() { }

#[test]
fn test_allow_trust_no_trustline() { }
```

### Task 12.4: Inflation Tests

```rust
#[test]
fn test_inflation_basic() { }

#[test]
fn test_inflation_no_winners() { }

#[test]
fn test_inflation_multiple_winners() { }

#[test]
fn test_inflation_winner_below_threshold() { }

#[test]
fn test_inflation_timing() { }
```

### Task 12.5: BumpSequence Complete Tests

```rust
#[test]
fn test_bump_sequence_basic() { }

#[test]
fn test_bump_sequence_lower_noop() { }

#[test]
fn test_bump_sequence_same_noop() { }

#[test]
fn test_bump_to_max() { }

#[test]
fn test_bump_overflow() { }
```

### Task 12.6: ManageData Complete Tests

```rust
#[test]
fn test_manage_data_create() { }

#[test]
fn test_manage_data_update() { }

#[test]
fn test_manage_data_delete() { }

#[test]
fn test_manage_data_name_too_long() { }

#[test]
fn test_manage_data_value_too_long() { }

#[test]
fn test_manage_data_low_reserve() { }

#[test]
fn test_manage_data_too_many_subentries() { }
```

---

## Phase 13: Soroban/InvokeHostFunction (Week 6+)

**C++ Reference:** `InvokeHostFunctionTests.cpp` (371 test sections)

This is the largest test file and covers smart contract execution. Recommend treating as a separate project given complexity.

Key areas:
- Contract deployment
- Contract invocation
- State management (footprint)
- Resource accounting
- TTL/archival
- Contract-to-contract calls
- Error handling

---

## Summary Checklist

### Infrastructure (Phase 0)
- [x] Test utilities module (test_utils.rs created)
- [ ] Sponsorship test helpers
- [ ] Multi-op test framework
- [x] INT64_MAX test helpers (partial)
- [ ] Protocol version macros

### Critical Tests (Phase 1)
- [x] All operations: too_many_subentries tests (ChangeTrust, ManageOffer, SetOptions, ManageData)
- [ ] All operations: INT64_MAX overflow tests
- [ ] Multi-operation transaction tests
- [x] Sequence number edge cases (AccountMerge seqnum tests)

### Per-Operation (Phases 2-12)
- [x] CreateAccount: 11 tests total (was 8 missing, added 3)
- [x] Payment: 24 tests total (was 15 missing, added 7)
- [x] AccountMerge: 14 tests total (was 15 missing, added 9)
- [x] ChangeTrust: 22 tests total (was 9 missing, added 3)
- [x] ManageOffer: 33 tests total (was 30+ missing, added 12)
- [x] PathPayment: 17 tests total (was 25+ missing, added 11)
- [x] SetOptions: 24 tests total (was 20 missing, added 6)
- [x] ClaimableBalance: 22 tests total (was 20 missing, added 4)
- [x] LiquidityPool: 13 tests total (was 20 missing, added 6)
- [x] Sponsorship: 15 tests total (was 15 missing, added 4)
- [x] Clawback: 12 tests total (was 7 missing, added 3)
- [x] SetTrustLineFlags: 11 tests total (was 6 missing, added 4)
- [x] AllowTrust: included in SetTrustLineFlags tests
- [x] Inflation: 3 tests total (was 5 missing, added 2)
- [x] BumpSequence: 6 tests total (was 5 missing, added 3)
- [x] ManageData: 14 tests total (has subentries tests)
- [x] OfferExchange: 8 tests total (new math utility tests)

### Soroban (Phase 13)
- [ ] InvokeHostFunction: 100+ tests (separate project)

### Progress Summary
- **Starting test count:** 370
- **Current test count:** 488
- **Tests added:** 118
- **Bugs fixed:** 2 (SetOptions subentries, ManageOffer check ordering)

---

## Execution Notes

1. **Parallelization:** Phases 2-12 can be parallelized across contributors after Phase 0/1 complete.

2. **Test Naming Convention:** Follow pattern `test_<operation>_<scenario>` for consistency.

3. **Documentation:** Each test should have a doc comment explaining what C++ test it corresponds to.

4. **Regression Prevention:** When a bug is found via CDP verification, add a test that would have caught it.

5. **Review Process:** Each phase should be reviewed against C++ test file to ensure no scenarios missed.
