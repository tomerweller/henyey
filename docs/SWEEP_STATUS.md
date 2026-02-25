# Verify-Execution Sweep Status

> **Updated**: 2026-02-25 04:10 UTC
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

## Running sweeps

| Sweep | Range | Status | Started |
|-------|-------|--------|---------|
| s16 | L59741312–L59841311 | running (100k chunk) | 2026-02-24 16:53 UTC |
| s17 | L59841312–L59941311 | running (100k chunk) | 2026-02-25 04:10 UTC |

## Tracker

| Status | PID | Started |
|--------|-----|---------|
| Synced | 2922836 | 2026-02-24 14:18 UTC (restarted with VE-08 fix) |
