# Verify-Execution Sweep Status

> **Updated**: 2026-02-27 19:10 UTC
> **Session**: b5e87aee (fresh start)
> **CDP data lake range**: L59501248–L61366079 (latest available as of 2026-02-23)
> **Supported protocol**: P24+ (L59501312 is first P24 ledger; L59501248–L59501311 are P23 and unverifiable)

## Protocol boundary

Protocol 24 activated at **L59501312** (exactly 64 ledgers after the cache start at L59501248).
Ledgers L59501248–L59501311 (P23) cannot be verified by Henyey (min supported: P24).

## Verified ranges

| Range | Status | Notes |
|-------|--------|-------|
| L59501248–L59501311 | **SKIPPED** | Protocol 23 — Henyey does not support P23 |
| L59501312–L59511311 | **CLEAN** | s1 completed — 10,000 ledgers, 0 mismatches |
| L59511312–L59521311 | **CLEAN** | s2 completed — 10,000 ledgers, 0 mismatches |
| L59521312–L59531311 | **CLEAN** | s3 completed — 10,000 ledgers, 0 mismatches |
| L59531312–L59541311 | **CLEAN** | s4 completed — 10,000 ledgers, 0 mismatches (VE-07 fix applied) |
| L59541312–L59551311 | **CLEAN** | s5 completed — 10,000 ledgers, 0 mismatches |
| L59551312–L59561311 | **CLEAN** | s6 completed — 10,000 ledgers, 0 mismatches |
| L59561312–L59571311 | **CLEAN** | s7 completed — 10,000 ledgers, 0 mismatches |
| L59571312–L59581311 | **CLEAN** | s8 completed — 10,000 ledgers, 0 mismatches |
| L59581312–L59591311 | **CLEAN** | s9 completed — 10,000 ledgers, 0 mismatches |
| L59591312–L59601311 | **CLEAN** | s10 completed — 10,000 ledgers, 0 mismatches |
| L59601312–L59611311 | **CLEAN** | s11 completed — 10,000 ledgers, 0 mismatches |
| L59611312–L59621311 | **CLEAN** | s12 completed — 10,000 ledgers, 0 mismatches |
| L59621312–L59631311 | **CLEAN** | s13 completed — 10,000 ledgers, 0 mismatches |
| L59631312–L59641311 | **CLEAN** | s14 completed — 10,000 ledgers, 0 mismatches (VE-08 fix applied) |
| L59641312–L59741311 | **CLEAN** | s15 completed — 100,000 ledgers, 0 mismatches |
| L59741312–L59841311 | **CLEAN** | s16 completed — 100,000 ledgers, 0 mismatches |
| L59841312–L59941311 | **CLEAN** | s17 completed — 100,000 ledgers, 0 mismatches |
| L59941312–L60041311 | **CLEAN** | s18 completed — 100,000 ledgers, 0 mismatches |
| L60041312–L60141311 | **CLEAN** | s19 completed — 100,000 ledgers, 0 mismatches |
| L60141312–L60241311 | **CLEAN** | s20 completed — 100,000 ledgers, 0 mismatches |
| L60241312–L60341311 | **CLEAN** | s21 completed — 100,000 ledgers, 0 mismatches |
| L60341312–L60441311 | **CLEAN** | s22 completed — 100,000 ledgers, 0 mismatches |
| L60441312–L60541311 | **CLEAN** | s23 completed — 100,000 ledgers, 0 mismatches |
| L60541312–L60641311 | **CLEAN** | s24 completed — 100,000 ledgers, 0 mismatches |
| L60641312–L60741311 | **CLEAN** | s25 completed — 100,000 ledgers, 0 mismatches (VE-10 fix applied) |
| L60741312–L60841311 | **CLEAN** | s26 completed — 100,000 ledgers, 0 mismatches |

## Previously confirmed bug fixes (from prior sessions)

- **VE-01**: Snapshot overwrite in `update_*` methods — fixed in `0fb052d`, `d482c43`
- **VE-02**: Pool share trustlines not loaded from bucket list — fixed in `710ae8d`
- **VE-03**: Fee-bump inner sig check ordering — fixed in `acf4472`
- **VE-04**: `check_signature_from_signers` 0>=0 bug — fixed in `3930486`
- **VE-05**: Spurious TTL INIT for read-only archived entries — fixed in `16933b2`
- **VE-06**: Hot archive keys collected for failed operations — fixed in `e8d22fa` + `7a172d7`

## Bug fixes (this session)

- **VE-07**: PreAuthTx signer removed before signature check — fixed in `f6948ba`
  - **Ledger**: L59531878, TX 91 (hash `9901cec6...`)
  - **Symptom**: txBAD_AUTH (ours) vs txSuccess (CDP) for a Payment with no signatures
  - **Root cause**: `remove_one_time_signers_from_all_sources` ran BEFORE `check_operation_signatures`. A prior TX in the same ledger added a PreAuthTx signer for this TX's hash, but our code consumed it before the signature check could see it.
  - **Fix**: Move signature checking to before one-time signer removal, matching stellar-core's ordering (checkAllTransactionSignatures → processSeqNum → checkOperationSignatures → removeOneTimeSignerFromAllSourceAccounts).

- **VE-08**: Signature check skipped for Soroban transactions — fixed in `dc2d81b`
  - **Ledger**: L59638512, TX 171 (hash `d9096fb5...`)
  - **Symptom**: txFeeBumpInnerSuccess (ours) vs txFeeBumpInnerFailed/TxBadAuth (CDP) for a fee-bump wrapping InvokeHostFunction. Fee pool off by 5782 stroops.
  - **Root cause**: The `!frame.is_soroban()` guard on the apply-time signature check skipped checking for all Soroban transactions. For fee-bump Soroban TXs, a prior TX in the same ledger modified the inner source's signer set, invalidating the inner signatures. stellar-core's `processSignatures()` calls `checkOperationSignatures()` for all transaction types.
  - **Fix**: Remove the `!frame.is_soroban()` guard so signature checking runs for all transaction types, matching stellar-core's behavior.

- **VE-09**: LedgerDelta merge rejects parallel cluster double-delete — fixed in `9e901ca`
  - **Ledger**: L61403915 (tracker catchup)
  - **Symptom**: Tracker crashed during catchup with "invalid merge: delete on deleted entry" in `LedgerDelta::merge`.
  - **Root cause**: Parallel Soroban clusters can independently delete the same entry (e.g. a TTL key present in multiple footprints). The merge logic rejected this as invalid, despite within-delta double-deletes already being handled as no-ops.
  - **Fix**: Make delete-on-deleted idempotent in the merge path, matching the within-delta behavior at line 383.

- **VE-10**: Deleted account reloaded from snapshot in parallel fee path — fixed in `07fbf59` + `0782a40`
  - **Ledger**: L60645316, TX 68 (hash `050055a3...`, account GBPHB57...)
  - **Symptom**: txSuccess (ours) vs TxNoAccount (CDP). Also fee=0 vs fee=100.
  - **Root cause**: In the parallel fee-deduction path, accounts are bulk-loaded into executor state via `state.load_entry()` (bypassing `load_account()`), so the `loaded_accounts` guard is never populated. When a prior TX in the ledger deletes the account via account_merge, a subsequent TX's `load_account` fell through to the bucket-list snapshot and returned the stale LIVE entry.
  - **Fix 1** (`07fbf59`): Add `delta().deleted_keys()` check to `load_account()` and `load_account_without_record()`, matching the existing pattern in `load_trustline` and `load_claimable_balance`.
  - **Fix 2** (`0782a40`): Override `result.fee_charged` with the pre-charged fee for validation failures in the parallel path, since the executor runs with `deduct_fee=false`.

## Running sweeps

| Sweep | Range | Status | Started |
|-------|-------|--------|---------|
| s27 | L60841312–L60941311 | running (100k chunk) | 2026-02-27 21:02 UTC |
| s28 | L60941312–L61041311 | starting (100k chunk) | 2026-02-27 22:00 UTC |

## Tracker

| Status | PID | Started |
|--------|-----|---------|
| Synced | 2563315 | 2026-02-27 21:02 UTC (restarted after s26 completed; caught up and tracking live at ~L61427925) |
