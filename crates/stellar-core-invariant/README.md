# stellar-core-invariant

Invariant framework for validating ledger state transitions in rs-stellar-core.

## Overview

This crate provides a comprehensive framework for defining and executing invariant checks that validate the correctness of ledger state transitions during ledger close operations. Invariants are pure validation functions that verify properties which must hold true after every ledger transition.

Invariant checking is a critical component of Stellar Core's safety model. By verifying that certain properties hold after each ledger close, we can detect bugs, state corruption, or consensus violations before they propagate through the network.

## Architecture

### Core Components

The framework consists of four main building blocks:

```
                    +-------------------+
                    | InvariantManager  |
                    |  - invariants[]   |
                    |  - check_all()    |
                    +--------+----------+
                             |
                             | runs each
                             v
+------------------+    +-----------+    +-------------------+
| InvariantContext |--->| Invariant |--->| InvariantError    |
| - prev_header    |    | - name()  |    | - Violated{name,  |
| - curr_header    |    | - check() |    |     details}      |
| - changes[]      |    | - strict? |    +-------------------+
| - bucket_hash    |    +-----------+
| - deltas         |
+------------------+
```

#### `Invariant` Trait

The core abstraction that all invariant validators implement. Each invariant has:

- **`name()`**: A unique identifier for error reporting and debugging.
- **`check(ctx)`**: The validation logic that receives an `InvariantContext` and returns `Ok(())` or an error.
- **`is_strict()`**: Whether violations should halt ledger close (default: `true`).

```rust
pub trait Invariant: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError>;
    fn is_strict(&self) -> bool { true }
}
```

#### `InvariantManager`

A registry that holds multiple invariants and executes them in sequence. It handles the distinction between strict and non-strict invariants:

- **Strict failures**: Cause `check_all()` to return immediately with the error.
- **Non-strict failures**: Are logged but do not halt processing.

#### `InvariantContext`

The context passed to invariants containing all information needed for validation:

| Field | Description |
|-------|-------------|
| `prev_header` | Ledger header before the transition |
| `curr_header` | Ledger header after the transition |
| `bucket_list_hash` | Computed hash for verification |
| `fee_pool_delta` | Net change in fee pool |
| `total_coins_delta` | Net change in total lumens |
| `changes` | All ledger entry changes |
| `full_entries` | Optional full state snapshot |
| `op_events` | Optional Soroban contract events |

#### `LedgerEntryChange`

Represents a single entry's state transition:

```rust
pub enum LedgerEntryChange {
    Created { current: LedgerEntry },
    Updated { previous: LedgerEntry, current: LedgerEntry },
    Deleted { previous: LedgerEntry },
}
```

## Built-in Invariants

### Header Invariants

These validate ledger header consistency:

| Invariant | Description | Strict |
|-----------|-------------|:------:|
| `LedgerSeqIncrement` | Ledger sequence increments by exactly 1 | Yes |
| `BucketListHashMatchesHeader` | Computed bucket list hash matches header | Yes |
| `CloseTimeNondecreasing` | Close time never decreases | Yes |
| `ConservationOfLumens` | Total coins and fee pool follow recorded deltas | No |

### Entry Validation Invariants

These validate individual ledger entry constraints:

| Invariant | Description | Strict |
|-----------|-------------|:------:|
| `LedgerEntryIsValid` | Comprehensive field validation for all entry types | No |
| `LastModifiedLedgerSeqMatchesHeader` | Entry timestamps match current header | No |
| `SponsorshipCountIsValid` | Sponsorship accounting is consistent | No |
| `AccountSubEntriesCountIsValid` | Subentry counts match actual entries | No |

### DEX Invariants

These validate order book and liability consistency:

| Invariant | Description | Strict |
|-----------|-------------|:------:|
| `LiabilitiesMatchOffers` | Liabilities consistent with offers and balances | No |
| `OrderBookIsNotCrossed` | No immediately matchable offers exist | Yes |

### Liquidity Pool Invariants

| Invariant | Description | Strict |
|-----------|-------------|:------:|
| `ConstantProductInvariant` | AMM pools maintain k = x * y (except withdrawals) | Yes |

### Soroban Invariants

| Invariant | Description | Strict |
|-----------|-------------|:------:|
| `EventsAreConsistentWithEntryDiffs` | SAC events match ledger entry changes | Yes |

## Strictness Levels

Invariants are either **strict** or **non-strict**:

- **Strict invariants** (default): Violations cause `check_all()` to return an error immediately, halting ledger close. Use for critical properties that, if violated, would break consensus or cause data corruption.

- **Non-strict invariants**: Violations are logged via `tracing::error!` but do not halt processing. Use for:
  - Invariants under active development
  - Edge cases being investigated
  - Properties that don't affect consensus correctness

## Usage

### Basic Setup

```rust
use stellar_core_invariant::{
    InvariantManager, InvariantContext, LedgerSeqIncrement,
    BucketListHashMatchesHeader, ConservationOfLumens, LedgerEntryIsValid,
};

// Create and configure the manager
let mut manager = InvariantManager::new();
manager.add(LedgerSeqIncrement);
manager.add(BucketListHashMatchesHeader);
manager.add(ConservationOfLumens);
manager.add(LedgerEntryIsValid);

// During ledger close, create context and check all invariants
let ctx = InvariantContext {
    prev_header: &prev_header,
    curr_header: &curr_header,
    bucket_list_hash: computed_hash,
    fee_pool_delta: fee_delta,
    total_coins_delta: coins_delta,
    changes: &entry_changes,
    full_entries: None,
    op_events: None,
};

if let Err(e) = manager.check_all(&ctx) {
    // Handle invariant violation - typically abort ledger close
    eprintln!("Invariant failed: {}", e);
}
```

### Creating Custom Invariants

```rust
use stellar_core_invariant::{Invariant, InvariantContext, InvariantError};

struct MyCustomInvariant;

impl Invariant for MyCustomInvariant {
    fn name(&self) -> &str {
        "MyCustomInvariant"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        // Access header information
        let protocol = ctx.curr_header.ledger_version;

        // Iterate over all changes
        for change in ctx.changes {
            if let Some(entry) = change.current_entry() {
                // Validate the entry...
                if some_condition_violated(entry) {
                    return Err(InvariantError::Violated {
                        name: self.name().to_string(),
                        details: "Explanation of what went wrong".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    fn is_strict(&self) -> bool {
        false // Non-strict: violations logged but don't halt
    }
}
```

### Soroban Event Validation

For validating SAC (Stellar Asset Contract) events:

```rust
use stellar_core_invariant::EventsAreConsistentWithEntryDiffs;

let network_id = stellar_core_common::NetworkId::mainnet();
let sac_invariant = EventsAreConsistentWithEntryDiffs::new(network_id.0);

let ctx = InvariantContext {
    // ... other fields ...
    op_events: Some(&contract_events),
    ..
};

manager.add(sac_invariant);
```

## Protocol Version Awareness

Many invariants adjust their validation logic based on the protocol version in `curr_header.ledger_version`. This ensures backward compatibility as new features are introduced:

| Protocol | Features |
|:--------:|----------|
| < 10 | No liabilities tracking |
| 10+ | Liabilities on accounts and trustlines |
| 13+ | AuthorizedToMaintainLiabilities flag |
| 14+ | Sponsorship (v1 entry extensions) |
| 17+ | Clawback, additional flags |
| 18+ | Liquidity pools, v2 extensions |
| 20+ | Soroban smart contracts |

## Validation Categories

### LedgerEntryIsValid Details

The `LedgerEntryIsValid` invariant performs comprehensive validation across all entry types:

**Account Entries:**
- Balance and sequence number are non-negative
- `num_sub_entries` does not exceed `i32::MAX`
- Account flags are within the valid mask for the protocol
- Home domain contains only printable ASCII
- Signers are in strictly increasing order by key
- Signer weights are valid (non-zero, within range)
- Extension fields match protocol version requirements
- `num_sub_entries + num_sponsoring` does not overflow

**Trustline Entries:**
- Asset is not native (trustlines are for non-native assets only)
- Asset code is valid (alphanumeric, proper padding)
- Limit is positive and balance is within range `[0, limit]`
- Flags are within the valid mask
- Authorized and AuthorizedToMaintainLiabilities are mutually exclusive
- Clawback flag cannot be enabled on an existing trustline
- Pool share trustlines have no liabilities

**Offer Entries:**
- Offer ID, amount, and price components are positive
- Selling and buying assets are valid
- Flags are within the valid mask

**Claimable Balance Entries:**
- Must be sponsored
- Has at least one claimant
- Amount is positive and asset is valid
- Claim predicates are valid (max depth 4, valid time bounds)
- Cannot be modified after creation (immutable)
- Clawback cannot be set on native asset

**Liquidity Pool Entries:**
- Cannot be sponsored
- Assets are valid and in lexicographic order (asset_a < asset_b)
- Fee is exactly 30 basis points
- Reserves and pool shares are non-negative
- Parameters cannot change after creation

**Contract Code Entries:**
- Hash matches the actual code content (SHA256)
- Code and hash cannot be modified after creation

**TTL Entries:**
- Key hash cannot change
- Live-until sequence cannot decrease

**Data Entries:**
- Name is non-empty
- Name contains only printable ASCII

### Liability Calculations

The `LiabilitiesMatchOffers` invariant validates that:

1. **Liability Consistency**: Changes in account/trustline liabilities match offer changes
2. **Authorization Rules**:
   - Fully unauthorized trustlines must have zero liabilities
   - "Authorized to maintain liabilities" trustlines cannot increase liabilities
3. **Balance Constraints**:
   - Account: `balance >= min_balance + selling_liabilities`
   - Account: `balance + buying_liabilities <= i64::MAX`
   - Trustline: `balance >= selling_liabilities`
   - Trustline: `limit - balance >= buying_liabilities`

The minimum balance formula is:
```
min_balance = (2 + num_sub_entries + num_sponsoring - num_sponsored) * base_reserve
```

## Design Principles

1. **Pure Functions**: Invariants should be stateless and have no side effects beyond validation.

2. **Fail Fast**: Return on the first violation found to provide clear error context.

3. **Thread Safety**: All invariants implement `Send + Sync` for potential parallel validation.

4. **Comprehensive Context**: The `InvariantContext` provides all necessary data; invariants should not perform I/O.

5. **Protocol Awareness**: Check `curr_header.ledger_version` before validating version-specific features.

## Status

Partial parity with upstream C++ stellar-core `src/invariant/*`. The framework is functional and actively used, though some edge cases may still be under development.
