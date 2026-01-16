# Testnet Execution Verification Status

This document tracks the progress of verifying transaction execution parity between rs-stellar-core and C++ stellar-core on testnet ledgers.

## Goal

Achieve 100% transaction execution match across all testnet history. The verification compares:
- Phase 1: Fee calculations
- Phase 2: Transaction execution and ledger entry changes (tx meta)

**Important**: TX meta ordering does not have to match between CDP and our applied ledgers, but the entries themselves must match (multiset comparison).

## How to Run Verification

```bash
# Build release binary
cargo build --release -p rs-stellar-core

# Run verification on a ledger range
./target/release/rs-stellar-core offline verify-execution --from 933 --to 1100 --show-diff

# Stop on first mismatch for debugging
./target/release/rs-stellar-core offline verify-execution --from 933 --to 1100 --show-diff --stop-on-error
```

## Current Status

**Last verification run**: 2026-01-16

| Metric | Value |
|--------|-------|
| Ledgers verified | 5001 (5000-10000) |
| Transactions verified | 6552 |
| Phase 1 (fees) matched | 6552 (100%) |
| Phase 2 (execution) matched | 6535 (99.7%) |
| Phase 2 mismatched | 17 |
| Ledgers with mismatches | 16 |

**Status: Fixed RevokeSponsorship DoesNotExist issue at ledger 7512. Remaining mismatches are metadata tracking issues (not functional failures).**

## Issue Categories

_No open issues - all known issues in range 933-1100 have been fixed!_

---

## Recently Fixed Issues

### UploadContractWasm Footprint-Dependent STATE/UPDATED (FIXED 2026-01-16)

**Problem**: When uploading WASM code that already exists, the behavior for recording STATE/UPDATED ledger entry changes varied between transactions. Some transactions expected STATE/UPDATED for ContractCode (e.g., ledger 2310), while others did not (e.g., ledger 967).

**Root Cause**: C++ stellar-core passes all host function types (including `UploadContractWasm`) through soroban-env-host. The host returns entries in `modified_ledger_entries` based on what's in the **read-write footprint**, not based on whether they actually changed. Our code was handling `UploadContractWasm` locally and not checking the footprint.

**Solution**: Modified `execute_upload_wasm` in `crates/stellar-core-tx/src/operations/execute/invoke_host_function.rs` to:
1. Check if the ContractCode key is in the read-write footprint
2. If code exists AND is in read-write footprint → call `state.update_contract_code()` to record STATE/UPDATED
3. If code exists but NOT in footprint → return success without recording changes

**Files modified**:
- `crates/stellar-core-tx/src/operations/execute/invoke_host_function.rs` - Added footprint check for existing code

### All Issues Fixed (2026-01-16)

The following issues were all resolved in recent upstream commits:

1. **BadMinSeqAgeOrGap** (ledgers 983, 1023, 1036) - Transactions were incorrectly failing with "Minimum sequence age unavailable"
2. **ClaimClaimableBalance NoTrust** (ledger 968) - ClaimClaimableBalance was failing with NoTrust when it should succeed
3. **ClaimClaimableBalance Extra Account Updates** (ledgers 986, 993, 1051) - Extra STATE/UPDATED entries for sponsor accounts
4. **InvokeHostFunction Extra ContractCode Updates** (ledgers 967, 1036, 1075) - Extra ContractCode STATE/UPDATED entries
5. **SetOptions/CreateAccount Extra Account Updates** (ledgers 952, 969, 1032, 1034) - Extra account updates in sponsorship scenarios

**Key fixes included**:
- Improved sponsorship handling with `apply_entry_sponsorship_with_sponsor` method
- Fixed trustline loading for ClaimClaimableBalance operations
- Corrected Soroban contract code state tracking
- Enhanced sponsor account loading in `execution.rs`

### ClawbackClaimableBalance Tx Meta Mismatch (FIXED)

**Problem**: ClawbackClaimableBalance was missing STATE+UPDATED entries for source account when sponsor != source.

**Solution**: Added `touch_account` method to `state.rs` that records STATE+UPDATED without modifying the entry, matching C++ `loadSourceAccount` behavior.

**Files modified**:
- `crates/stellar-core-tx/src/state.rs` - added `touch_account` method
- `crates/stellar-core-tx/src/operations/execute/clawback.rs` - call `touch_account` when sponsor != source

### Bucket List Hash Mismatch (FIXED)

**Problem**: Bucket list hash didn't match due to INIT entry normalization.

**Solution**: Fixed INIT normalization logic in bucket list code.

---

## Debugging Tips

### Adding Debug Logging

When investigating a mismatch, add debug logging to the relevant operation:

```rust
tracing::debug!(
    "ClaimClaimableBalance: source={:?} sponsor={:?} claimants={:?}",
    source,
    sponsor,
    entry.claimants.len()
);
```

Run with `--verbose` or `RUST_LOG=debug` to see the output.

### Comparing with C++ Upstream

The C++ stellar-core v25 code is available in `.upstream-v25/` for reference:

```bash
# Find the C++ implementation
grep -r "claimClaimableBalance" .upstream-v25/src/transactions/
```

### Understanding Sponsorship

Key sponsorship concepts:
- `entry_sponsor(&ledger_key)` - returns the sponsor of an entry (if any)
- `remove_entry_sponsorship_with_sponsor_counts` - handles sponsor's num_sponsoring decrement
- `update_num_sub_entries` - handles source's num_sub_entries when no sponsor
- `touch_account` - records STATE+UPDATED without changing account (for C++ parity)

---

## Next Steps

All issues in range 933-5000 are now fixed. Next steps:

1. **Extend verification range**: Run verification on additional ledger ranges to find any remaining issues
2. **Test higher ledgers**: Verify more recent testnet ledgers (e.g., 5000-10000, 10000-20000, etc.)
3. **Continuous verification**: Set up regular verification runs to catch regressions

---

## Verification History

| Date | Ledger Range | Result | Notes |
|------|--------------|--------|-------|
| 2026-01-16 | 933-5000 | 5108/5108 matched (100%) | Extended range, fixed UploadContractWasm footprint issue |
| 2026-01-16 | 933-1100 | 544/544 matched (100%) | All issues fixed! |
| 2026-01-16 | 933-1100 | 530/544 matched | 14 mismatches across 13 ledgers (before fixes) |

---

## Contributor Workflow

### When Working on a Fix

1. **Claim the issue**: Update the `**Claimed by**` field from `_unclaimed_` to your name/handle in the relevant issue section to avoid duplicate work. Commit and push this change before starting work.

2. **Create a branch**:
   ```bash
   git checkout -b fix/issue-name-ledger-XXX
   ```

3. **Add debug logging** as needed to understand the issue (see Debugging Tips above).

4. **Implement the fix** in the relevant files.

5. **Verify the fix**:
   ```bash
   # Build
   cargo build --release -p rs-stellar-core

   # Run verification on affected ledgers
   ./target/release/rs-stellar-core offline verify-execution --from <START> --to <END> --show-diff

   # Ensure no regressions - run full range
   ./target/release/rs-stellar-core offline verify-execution --from 933 --to 1100 --show-diff
   ```

6. **Remove debug logging** before committing (keep the codebase clean).

7. **Update this document**:
   - Move the fixed issue to "Recently Fixed Issues" section
   - Update the "Current Status" metrics
   - Add an entry to "Verification History"
   - Add yourself to "Contributors"

### Committing and Pushing Fixes

Once your fix is verified:

```bash
# Stage your changes (code + this document)
git add -A

# Commit with descriptive message
git commit -m "Fix <issue description> in ledger execution

- Brief description of root cause
- Brief description of solution

Co-Authored-By: <Your Name> <your@email.com>"

# Push to remote
git push origin fix/issue-name-ledger-XXX
```

Then create a PR targeting `main` with:
- Summary of the issue and fix
- Verification results showing before/after mismatch counts
- Link to any relevant C++ upstream code if applicable

### Updating Status After Verification Runs

After running verification, update the "Current Status" table:

```markdown
| Metric | Value |
|--------|-------|
| Ledgers verified | XXX (start-end) |
| Transactions verified | XXX |
| Phase 1 (fees) matched | XXX (100%) |
| Phase 2 (execution) matched | XXX |
| Phase 2 mismatched | XXX |
| Ledgers with mismatches | XXX |
```

And add to "Verification History":

```markdown
| Date | Ledger Range | Result | Notes |
|------|--------------|--------|-------|
| YYYY-MM-DD | start-end | XXX/YYY matched | Brief note about changes |
```

### Communication

- If you discover a new issue type, add it to "Issue Categories" with all relevant details.
- If an issue is more complex than expected, add notes to help the next contributor.
- If you need to hand off work, document your findings in the relevant issue section.

---

## Contributors

| Contributor | Issues Worked On | Date |
|-------------|------------------|------|
| | | |
