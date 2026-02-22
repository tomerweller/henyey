# Verify-Execution Sweep Status

> **Updated**: 2026-02-22 14:48
> **CDP data lake range**: L59501248–L61339818 (latest available as of 2026-02-21)
> **Supported protocol**: P24+ (L59501312 is first P24 ledger; L59501248–L59501311 are P23 and unverifiable)
> **P25 boundary**: TBD (to be identified during sweeps)

## Protocol boundary

Protocol 24 activated at **L59501312** (exactly 64 ledgers after the cache start at L59501248).
Ledgers L59501248–L59501311 (P23) cannot be verified by Henyey (min supported: P24).
Protocol 25 boundary: TBD — to be identified during Sweep 4 of L59939047+.

## Verified ranges

| Range | Status | Notes |
|-------|--------|-------|
| L59501248–L59501311 | **SKIPPED** | Protocol 23 — Henyey does not support P23 |
| L59501312–L59659967 | **CLEAN** | Sweep 1 completed — 158,656 ledgers, 0 mismatches |
| L59659968–L59747049 | **CLEAN** | Sweep 2 ran clean up to VE-03 |
| L59747050 | **CLEAN** | VE-03 confirmed fixed — verified with 0 mismatches post-fix (commit acf4472) |
| L59747051–L59799999 | **CLEAN** | Sweep 2 restart completed — 52,949 ledgers, 0 mismatches |
| L59800000–L59845022 | **CLEAN** | Sweep 3 ran through these ledgers with no hash mismatches |
| L59845023 | **CLEAN** | VE-02 confirmed fixed — verified with 0 mismatches post-fix (commit 710ae8d) |
| L59845024–L59863186 | **CLEAN** | Sweep 3 restart ran clean up to VE-04 |
| L59863187 | **CLEAN** | VE-04 confirmed fixed — verified with 0 mismatches post-fix (commit 3930486) |
| L59863188–L59875307 | **CLEAN** | Sweep 3 restart 3 ran clean through this range |
| L59875308–L59907177 | **CLEAN** | Sweep 3a completed — 31,870 ledgers, 0 mismatches |
| L59907178–L59939046 | **CLEAN** | Sweep 3b completed — 31,869 ledgers, 0 mismatches |
| L59939047–L60139046 | In progress (s4a, PID 3710662) | No errors found so far |
| L60139047–L60339046 | In progress (s4b, PID 3710664) | No errors found so far |
| L60339047–L60539046 | In progress (s4c, PID 3710665) | No errors found so far |
| L60539047–L60739046 | Pending | Queued — starts when a slot opens |
| L60739047–L60939046 | Pending | Queued — starts when a slot opens |
| L60939047–L61139046 | Pending | Queued — starts when a slot opens |
| L61139047–L61339818 | Pending | Queued — starts when a slot opens |

## VE-04 (confirmed fixed)

- **Ledger**: L59863187
- **Transaction**: TX 124 (hash a90e1a0c...), ops 2,3,4,6,7,9 returning `opNO_ACCOUNT` (ours) vs `opBAD_AUTH` (CDP)
  for per-op source `GAXWT6262PRQCYOEO7QFCI3DTATF2DBDSA67NHWSCA6VCUVDUBSBMG7K`.
- **Root cause**: `check_signature_from_signers` returned `total_weight >= needed_weight` at the end,
  evaluating `0 >= 0 = true` even when no signer matched. TX 69 (earlier in same ledger) merged GAXWT6262
  into GDVAAPR. TX 124's custodian key (an additional signer) was in the envelope, but GAXWT6262's master
  key was not. `check_signature_no_account` created a synthetic signer for the master key only and called
  `check_signature_from_signers` with `needed_weight=0`. No signer matched, but the function returned `true`
  (the `0 >= 0` bug), allowing the ops to execute and hit `opNO_ACCOUNT`.
  Stellar-core's `SignatureChecker::checkSignature` falls through to `return false` when nothing matched,
  producing `opBAD_AUTH`.
- **Fix**: Changed final return to `total_weight >= needed_weight && total_weight > 0`.
- **Fixed**: Commit `3930486` (2026-02-21).
- **Confirmed**: Single-ledger verify-execution on L59863187 passed with 0 mismatches post-fix.

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
| s4a | L59939047-L60139046 | 3710662 | 2026-02-22 |
| s4b | L60139047-L60339046 | 3710664 | 2026-02-22 |
| s4c | L60339047-L60539046 | 3710665 | 2026-02-22 |

Monitor PID: 3902604 (10-min interval)
