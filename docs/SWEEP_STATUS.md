# Verify-Execution Sweep Status

> **Updated**: 2026-02-21
> **Mainnet cache range**: L59501248–L59939046
> **Supported protocol**: P24+ (L59501312 is first P24 ledger; L59501248–L59501311 are P23 and unverifiable)

## Protocol boundary

Protocol 24 activated at **L59501312** (exactly 64 ledgers after the cache start at L59501248).
Ledgers L59501248–L59501311 (P23) cannot be verified by Henyey (min supported: P24).

## Verified ranges

| Range | Status | Notes |
|-------|--------|-------|
| L59501248–L59501311 | **SKIPPED** | Protocol 23 — Henyey does not support P23 |
| L59501312–L59659967 | **CLEAN** | Sweep 1 completed — 158,656 ledgers, 0 mismatches |
| L59659968–L59747049 | **CLEAN** | Sweep 2 ran clean up to VE-03 |
| L59747050 | **CLEAN** | VE-03 confirmed fixed — verified with 0 mismatches post-fix (commit acf4472) |
| L59747051–L59799999 | In progress (Sweep 2 restart, PID 3255803) | No errors found so far |
| L59800000–L59845022 | **CLEAN** | Sweep 3 ran through these ledgers with no hash mismatches |
| L59845023 | **CLEAN** | VE-02 confirmed fixed — verified with 0 mismatches post-fix (commit 710ae8d) |
| L59845024–L59863186 | **CLEAN** | Sweep 3 restart ran clean up to VE-04 |
| L59863187–L59939046 | In progress (Sweep 3 restart 2, PID 3256156) | Testing if VE-04 also fixed by VE-03 fix |

## VE-03 (confirmed fixed)

- **Ledger**: L59747050
- **Transaction**: TX 187 (hash 472d28944e2a6a73...), a fee-bump with `txFeeBumpInnerFailed/TxBadAuth`
- **Root cause**: `validate_preconditions()` checked inner transaction signatures before fee charging.
  A prior transaction in the same ledger had removed a signer from the inner source account,
  so the inner sig check failed in `validate_preconditions()` and returned early with `fee_charged=0`.
  In stellar-core, `processFeeSeqNum()` charges the outer fee BEFORE `apply()` re-validates inner sigs.
- **Fix**:
  - Removed inner sig check for fee-bump txs from `validate_preconditions()` (outer/fee-source check kept).
  - Fixed `check_operation_signatures()` Step 1 to return `InvalidSignature` (instead of `None`) when
    TX-level source sig check fails — this runs after the outer fee has been deducted.
- **Fixed**: Commit `acf4472` (2026-02-21).
- **Confirmed**: Single-ledger verify-execution on L59747050 passed with 0 mismatches post-fix.

## VE-02 (confirmed fixed)

- **Ledger**: L59845023
- **Root cause**: `find_pool_share_trustlines_for_asset` only searched in-memory state. Pool share
  trustlines for account 39c2c208 in RUV/XLM and RUV/SHX pools were in the bucket list but
  never loaded into memory. `redeem_pool_share_trustlines` returned early with nothing to redeem.
- **Fix**: Added secondary index `pool_share_tl_account_index` (account → pool IDs) built during
  bucket list scan; added `load_pool_share_trustlines_for_account_and_asset` called from
  `SetTrustLineFlags`/`AllowTrust` operation loading to pre-load pool share TLs via the index.
- **Fixed**: Commit `710ae8d` (2026-02-21).
- **Confirmed**: Single-ledger verify-execution on L59845023 passed with 0 mismatches post-fix.

## VE-01 (confirmed fixed)

- **Bug**: Snapshot overwrite in 5 `update_*` methods corrupted `rollback_to_savepoint`.
- **Fixed**: Commits `0fb052d` (contract_data/code), `d482c43` (account/data/claimable_balance).
- **Confirmed**: Post-fix sweep passed L59658059 without error (2026-02-20).

## Running sweeps

| Sweep | Range | PID | Started |
|-------|-------|-----|---------|
| Sweep 2 (restart) | L59747051–L59799999 | 3255803 | 2026-02-21 |
| Sweep 3 (restart 2) | L59863187–L59939046 | 3256156 | 2026-02-21 |
