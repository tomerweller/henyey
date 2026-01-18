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

## 3. Ed25519SignedPayload Extra Signer Verification (RESOLVED)

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

## 4. Soroban CPU Metering Difference (RESOLVED)

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

## 5. Credit Asset Self-Payment Order of Operations (RESOLVED)

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

## 6. ClaimClaimableBalance Issuer NoTrust (RESOLVED)

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
After fix: 481 transactions in range 37040-37320 verified with 0 mismatches (InvokeHostFunction issue at ledger 37046 also resolved - see Issue #7).

---

## 7. Soroban Archived Entry TTL Restoration (RESOLVED)

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
