## C++ Parity Status

This section documents the parity between this Rust crate and the upstream C++ stellar-core `src/invariant/` directory.

### Implemented

The following invariants and components have been implemented in Rust:

| Rust Implementation | C++ Counterpart | Notes |
|---------------------|-----------------|-------|
| `InvariantManager` | `InvariantManager` / `InvariantManagerImpl` | Core registry and executor |
| `Invariant` trait | `Invariant` class | Base abstraction for all invariants |
| `InvariantError::Violated` | `InvariantDoesNotHold` exception | Error handling mechanism |
| `InvariantContext` | `LedgerTxnDelta` + operation params | Context passed to invariants |
| `LedgerEntryChange` | Entry changes in `LedgerTxnDelta` | Entry state transitions |
| `LedgerSeqIncrement` | (implicit in header validation) | Ledger sequence validation |
| `BucketListHashMatchesHeader` | (implicit in bucket validation) | Bucket list hash verification |
| `CloseTimeNondecreasing` | (implicit in header validation) | Close time monotonicity |
| `ConservationOfLumens` | `ConservationOfLumens` | Total coins and fee pool tracking |
| `LedgerEntryIsValid` | `LedgerEntryIsValid` | Comprehensive entry validation |
| `LastModifiedLedgerSeqMatchesHeader` | Part of `LedgerEntryIsValid` | Entry timestamp validation |
| `SponsorshipCountIsValid` | `SponsorshipCountIsValid` | Sponsorship accounting |
| `AccountSubEntriesCountIsValid` | `AccountSubEntriesCountIsValid` | Subentry count validation |
| `LiabilitiesMatchOffers` | `LiabilitiesMatchOffers` | Liability consistency with offers |
| `OrderBookIsNotCrossed` | `OrderBookIsNotCrossed` | DEX crossing detection |
| `ConstantProductInvariant` | `ConstantProductInvariant` | AMM k=x*y validation |
| `EventsAreConsistentWithEntryDiffs` | `EventsAreConsistentWithEntryDiffs` | SAC event/entry consistency |

### Not Yet Implemented (Gaps)

The following C++ invariants and features are **not yet implemented** in Rust:

#### Missing Invariants

| C++ Invariant | Description | Priority |
|--------------|-------------|----------|
| `BucketListIsConsistentWithDatabase` | Validates that BucketList entries match database state during catchup. Checks LIVEENTRY/DEADENTRY consistency. | Medium |
| `ArchivedStateConsistency` | Validates Soroban state archival consistency. Ensures no entry exists in both live and hot archive BucketLists simultaneously. | Medium |

#### Missing Check Hooks

The C++ `Invariant` base class supports multiple check hooks that trigger at different points in the ledger lifecycle:

| C++ Method | Rust Support | Description |
|------------|:------------:|-------------|
| `checkOnOperationApply()` | Partial | Called after each operation. Rust uses `check()` with ledger-level context instead of per-operation. |
| `checkOnBucketApply()` | No | Called during bucket apply (catchup). Used by `BucketListIsConsistentWithDatabase`. |
| `checkAfterAssumeState()` | No | Called after assuming state from buckets. |
| `checkOnLedgerCommit()` | No | Called on ledger commit with eviction/restoration data. Used by `ArchivedStateConsistency`. |
| `checkSnapshot()` | No | Background invariant check against full ledger state snapshot. |

#### Missing InvariantManager Features

| C++ Feature | Rust Support | Description |
|-------------|:------------:|-------------|
| Dynamic registration | Partial | C++ uses `registerInvariant()` with `Application` context |
| Dynamic enable/disable | No | C++ supports runtime `enableInvariant(name)` |
| JSON info reporting | No | C++ provides `getJsonInfo()` for status reporting |
| Failure tracking | No | C++ tracks `InvariantFailureInformation` per invariant |
| Metrics integration | No | C++ integrates with `medida` metrics (failure counts, etc.) |
| Background snapshot timer | No | C++ has `mStateSnapshotTimer` for periodic background checks |
| Fuzzer support | No | C++ has `snapshotForFuzzer()` / `resetForFuzzer()` hooks |
| Bucket apply invariant flag | No | C++ has `isBucketApplyInvariantEnabled()` |

#### Missing Entry Type Validation

In `LedgerEntryIsValid`, the following entry types have limited or no validation compared to C++:

| Entry Type | Gap |
|------------|-----|
| `ConfigSettingEntry` | Not validated in Rust |
| `ContractDataEntry` | Limited validation (only balance key extraction for SAC) |

### Implementation Notes

#### Architectural Differences

1. **Check Granularity**: The C++ implementation checks invariants at the operation level (`checkOnOperationApply`), while Rust checks at the ledger level via `InvariantContext`. This is a deliberate simplification that trades per-operation error context for simpler integration.

2. **Context vs Parameters**: Rust uses a unified `InvariantContext` struct, while C++ passes individual parameters (`Operation`, `OperationResult`, `LedgerTxnDelta`, events, `AppConnector`).

3. **Stateless vs Stateful**: Most Rust invariants are stateless unit structs. C++ `OrderBookIsNotCrossed` maintains internal state (`mOrderBook`) for incremental updates - the Rust version requires full order book in context.

4. **Error Handling**: Rust uses `Result<(), InvariantError>` while C++ returns error message strings (empty = success) and may throw `InvariantDoesNotHold` exception.

5. **Strictness**: Both implementations support strict/non-strict distinction. Rust defaults to strict (`is_strict() -> true`), matching C++ behavior.

6. **Application Context**: C++ invariants often take `Application&` for database/bucket access. Rust invariants are pure and receive all needed data via `InvariantContext`.

#### Database/Storage Independence

The Rust implementation is designed to be storage-agnostic:
- No direct database queries
- No bucket list iteration
- All state provided via `InvariantContext`

This is intentional for modularity but means `BucketListIsConsistentWithDatabase` would require different architecture to implement.

#### Protocol Version Handling

Both implementations are protocol-version aware. Rust checks `ctx.curr_header.ledger_version` for version-specific validation. Key thresholds match C++:
- Protocol 10: Liabilities
- Protocol 13: AuthorizedToMaintainLiabilities
- Protocol 14: Sponsorship
- Protocol 17: Clawback
- Protocol 18: Liquidity pools
- Protocol 20+: Soroban

### Testing Status

| Test Category | Coverage |
|--------------|----------|
| Unit tests | Partial - basic invariant tests in `mod tests` |
| Integration tests | None - no ledger simulation |
| Fuzzer integration | None |

The C++ tests in `src/invariant/test/` provide comprehensive coverage including:
- `InvariantTests.cpp` - Framework tests
- `AccountSubEntriesCountIsValidTests.cpp`
- `BucketListIsConsistentWithDatabaseTests.cpp`
- `ConservationOfLumensTests.cpp`
- `LedgerEntryIsValidTests.cpp`
- `LiabilitiesMatchOffersTests.cpp`
- `OrderBookIsNotCrossedTests.cpp`
- `SponsorshipCountIsValidTests.cpp`

### Recommendations for Closing Gaps

1. **High Priority**: Add per-operation context to enable `checkOnOperationApply` semantics if needed for debugging.

2. **Medium Priority**: Implement `BucketListIsConsistentWithDatabase` if bucket/database consistency checking is required - would need storage trait abstraction.

3. **Medium Priority**: Implement `ArchivedStateConsistency` when Soroban state archival is integrated.

4. **Lower Priority**: Add metrics, JSON reporting, and dynamic enable/disable for production observability.

5. **Testing**: Port C++ test cases to Rust, especially edge cases in `LedgerEntryIsValidTests` and `LiabilitiesMatchOffersTests`.
