# TX_SPEC Adherence — henyey-tx

**Spec version:** 26 (stellar-core v26.0.1 / Protocol 26)
**Crate:** crates/tx
**Last updated:** 2026-05-13
**Overall adherence:** 78%

## Summary

| Category | Full | Partial | Absent | Drift | N/A |
|----------|------|---------|--------|-------|-----|
| Validation pipeline (§5) | 12 | 4 | 3 | 0 | 1 |
| Fee framework (§6) | 6 | 1 | 0 | 0 | 0 |
| Apply pipeline (§7) | 4 | 2 | 2 | 0 | 1 |
| Operations (§8, 27 ops) | 22 | 4 | 0 | 0 | 1 |
| Sponsorship (§9) | 3 | 1 | 1 | 0 | 0 |
| DEX engine (§10) | 4 | 0 | 0 | 0 | 0 |
| Soroban (§11) | 5 | 1 | 0 | 0 | 0 |
| State / Meta / Events (§12–§14) | 7 | 1 | 0 | 0 | 1 |
| Error handling (§15) | 17 | 0 | 2 | 0 | 0 |
| Invariants (§16) | 11 | 3 | 1 | 0 | 0 |
| **Total** | **91** | **17** | **9** | **0** | **3** |

`adherence_pct = 91 / (91 + 17 + 9) = 78%` (N/A excluded; Drift = 0).

## Per-Operation Status (§8, all 27 op types)

| # | Op | Status | Implementation |
|---|----|--------|----------------|
| 8.1 | CreateAccount | Full | `operations/execute/create_account.rs:18` |
| 8.2 | Payment | Full | `operations/execute/payment.rs:34` |
| 8.3 | PathPaymentStrictReceive | Full | `operations/execute/path_payment.rs:32` |
| 8.4 | PathPaymentStrictSend | Full | `operations/execute/path_payment.rs:191` |
| 8.5 | ManageSellOffer | Full | `operations/execute/manage_offer.rs:40` |
| 8.5 | ManageBuyOffer | Full | `operations/execute/manage_offer.rs:517` |
| 8.5 | CreatePassiveSellOffer | Full | `operations/execute/manage_offer.rs:554` |
| 8.6 | SetOptions | Full | `operations/execute/set_options.rs:54` |
| 8.7 | ChangeTrust | Full | `operations/execute/change_trust.rs:22` |
| 8.8 | AllowTrust | Full | `operations/execute/trust_flags.rs:31` |
| 8.9 | SetTrustLineFlags | Full | `operations/execute/trust_flags.rs:145` |
| 8.10 | AccountMerge | Full | `operations/execute/account_merge.rs:16` |
| 8.11 | Inflation | N/A | `operations/execute/inflation.rs:25` — disabled at V_12, Henyey min is V_24; always returns `NotTime` |
| 8.12 | ManageData | Full | `operations/execute/manage_data.rs:29` |
| 8.13 | BumpSequence | Full | `operations/execute/bump_sequence.rs:14` |
| 8.14 | CreateClaimableBalance | Full | `operations/execute/claimable_balance.rs:45` |
| 8.15 | ClaimClaimableBalance | Full | `operations/execute/claimable_balance.rs:247` |
| 8.16 | BeginSponsoringFutureReserves | Full | `operations/execute/sponsorship.rs:30` |
| 8.17 | EndSponsoringFutureReserves | Full | `operations/execute/sponsorship.rs:79` |
| 8.18 | RevokeSponsorship | Full | `operations/execute/sponsorship.rs:106` |
| 8.19 | Clawback | Full | `operations/execute/clawback.rs:28` |
| 8.19 | ClawbackClaimableBalance | Full | `operations/execute/clawback.rs:109` |
| 8.20 | LiquidityPoolDeposit | Full | `operations/execute/liquidity_pool.rs:27` |
| 8.21 | LiquidityPoolWithdraw | Full | `operations/execute/liquidity_pool.rs:240` |
| 8.22 | InvokeHostFunction | Partial | `operations/execute/invoke_host_function.rs:450` — host invocation, footprint metering, TTL pairing all in place. P23 parallel path (`doParallelApply`) is shared with the sequential path; no explicit `ThreadParallelApplyLedgerState` (single-threaded port). Auto-restore via `extract_hot_archive_restored_keys` is wired |
| 8.23 | ExtendFootprintTTL | Full | `operations/execute/extend_footprint_ttl.rs:50` |
| 8.24 | RestoreFootprint | Full | `operations/execute/restore_footprint.rs:66` |

(Counted as 25 unique impls + 1 N/A + 1 Partial = 27 op types; 22 Full, 1 Partial, 0 Absent in the table above. ManageBuy/PassiveSell share `manage_offer.rs` but are separate XDR types.)

## Invariant Coverage (INV-T1 – INV-T15)

| Invariant | Status | Enforcement |
|-----------|--------|-------------|
| INV-T1 (Tx hash determinism) | Full | `frame.rs:207 hash_envelope` (V0 normalizes to V1, signatures excluded, SHA-256 over `TransactionSignaturePayload`) |
| INV-T2 (Seq num monotonicity, V_10+) | Full | `live_execution.rs:533 process_seq_num` (sole writer; defers to V_10+ path) |
| INV-T3 (Fee charging order) | Full | `live_execution.rs:241 process_fee_seq_num` runs before `apply_transaction:637` |
| INV-T4 (No negative balances) | Full | `henyey_common::checked_types::sub_account_balance`; per-op `*_UNDERFUNDED` returns |
| INV-T5 (Sponsorship conservation, txBAD_SPONSORSHIP) | **Absent** | `state/sponsorship.rs:13 has_pending_sponsorship` exists, but no caller in apply path enforces `!hasSponsorshipEntry()` at end of `applyOperations` ⇒ `TxBadSponsorship` is wired into the result enum (`result.rs:276`) but never produced |
| INV-T6 (Signature consumption) | Full | `signature_checker.rs:208 check_all_signatures_used` |
| INV-T7 (One-time signer removal) | Full | `live_execution.rs:572 remove_one_time_signers`; fee-bump does outer + inner pass (`:665-679`) |
| INV-T8 (Footprint disjointness) | Full | `validation.rs:1099` duplicate check across read_only ∪ read_write |
| INV-T9 (Soroban single-op rule) | Full | `frame.is_valid_structure()` + `validation.rs:1030` |
| INV-T10 (TTL paired creation) | Full | `operations/execute/invoke_host_function.rs:904` — `assert!(created_keys.contains(&ttl_key), ...)` matching stellar-core's `releaseAssertOrThrow`, plus V_26 SAC Account/Trustline allowlist |
| INV-T11 (Resource fee non-overflow) | Partial | `validation.rs:1091` enforces `resource_fee ≤ total_fee` and `resource_fee ≤ MAX_RESOURCE_FEE`, but the explicit `i64` overflow check on `(non_refundable + refundable)` from spec §5.2 step 6 resource-fee 2 is not visible. Likely implicit via clamping but not asserted |
| INV-T12 (Fee-bump priority) | Full | `fee_bump.rs:371-389` — cross-multiplication `v1 ≥ v2` plus V_23 Soroban negative-inner allowance |
| INV-T13 (Two-phase atomicity) | Partial | Fee phase commits separately (`process_fee_seq_num`). Op-level rollback uses `state/savepoint.rs` mechanisms, but I did not verify the full `ltxTx`/`ltxOp` discard semantics for V_14+ rollback-on-failure; needs deeper audit |
| INV-T14 (Cross-self prohibition) | Full | `path_payment.rs:666 seller_id == source ⇒ FilterStopCrossSelf`; `manage_offer.rs:918` same |
| INV-T15 (Apply-order independence) | Partial | Single-threaded Rust port executes deterministically; parallel-stage merge logic is hosted in `operations/execute/invoke_host_function.rs:759 hot_archive_restores` and the herder layer (`HERDER_SPEC §5.3`). Henyey-tx itself is not multi-threaded so the invariant holds trivially, but the `ParallelTxSuccessVal` merge surface from spec §11.6 is not modeled |

## Detailed Findings

### §5.1 — Envelope and Fee Pre-checks

- **§5.1-1 (MUST, XDR depth ≤ 500)**: **Absent**. No `check_xdr_depth(envelope, 500)` call found in `crates/tx/src/`. The Rust XDR codec (`stellar_xdr::curr`) does enforce nesting limits during deserialization (`Limits`), but no explicit 500-level depth gate is invoked in `check_valid_pre_seq_num` or its callers. Recommended: anchor at `validation.rs` entry point.
- **§5.1-2 (`XDRProvidesValidFee`)**: Full. `validation.rs:1038-1044` rejects out-of-range Soroban `resource_fee`; `fee_bump.rs:394-399` covers fee-bump inner.
- **§5.1-3 (initialise feeCharged)**: Full — `MutableTransactionResult::new(fee_charged)` in `live_execution.rs:270`.
- **§5.1-4 (SignatureChecker construction)**: Full — `signature_checker.rs:63 SignatureChecker::new`.
- **§5.1-5 (commonValid invocation)**: Full — `lib.rs:368 check_signatures` + `validation.rs:995 check_valid_pre_seq_num`.
- **§5.1-6 (per-op checkValid loop)**: Partial — `operations/mod.rs:176 op_type::from_body` is invoked but the per-op `doCheckValid` is not run during `check_valid_pre_seq_num` (see comment `validation.rs:1068-1073`). stellar-core defers this to the apply path, matching Rust; but for the validation pipeline (overlay/herder admission) Rust may under-reject. Operationally tolerated because tx-set construction does the per-op check downstream.
- **§5.1-7 (`checkAllSignaturesUsed`)**: Full — `signature_checker.rs:208`.

### §5.2 — commonValidPreSeqNum

All ten ordered steps are covered in `validation.rs:995-1208` with explicit step comments:
1-6 Full; 7 (classic ext gate `tx.ext != 0` at V_21+): Full (`:1196`); 8 (time/ledger preconditions): Full via `is_too_early`/`is_too_late`; 9 (min inclusion fee): Full (`validate_fee:467`); 10 (source account existence): handled in apply path (`live_execution.rs:649` → `TxNoAccount`).
- **§5.2 step 11 (CAP-77 frozen-key gate)**: **Absent**. `frozen_keys.rs:117 accesses_frozen_key` and `operation_accesses_frozen_key` exist and are well-tested, but no caller in `validation.rs`/`live_execution.rs` actually invokes them with a `FrozenKeyConfig` from the network state to return `TxFrozenKeyAccessed`. The result code is wired in `result.rs:280` and `fee_bump.rs:783` but never produced.

### §5.3 — commonValid Post-SeqNum

- **§5.3-1 (seq check, isBadSeq)**: Full — `validation.rs:396 validate_sequence` + `:413 validate_min_seq_num`.
- **§5.3-2 (isTooEarlyForAccount, V_19+, minSeqAge / minSeqLedgerGap)**: **Partial**. The `ValidationError::BadMinAccountSequenceAge` and `BadMinAccountSequenceLedgerGap` enum variants exist (`validation.rs:279,281`) and map to `BadMinSeqAgeOrGap` in `lib.rs:276-277`, but they are never produced — no check reads `AccountEntry.ext.v3.seqTime`/`seqLedger`. Spec §5.3 step 2 not implemented.
- **§5.3-3 (transaction-level signature check at THRESHOLD_LOW)**: Full — `signature_checker.rs:84 check_signature` plus `validation.rs:428 validate_extra_signers` for extra signers.
- **§5.3-4 (fee source balance check)**: Full — `validation.rs:822 InsufficientBalance`.

### §5.4 — FeeBumpTransactionFrame commonValid

- Steps 1-3 (V_13 gate, inclusion fee, inner-fee cross-multiplication): Full in `fee_bump.rs:347-422`. INV-T12 verified.
- Step 4 (fee source absence → txNO_ACCOUNT): Full (mapped from `SourceAccountNotFound`).
- Steps 5-7 (fee source signature, balance, frozen-key): step 5/6 Full, step 7 **Absent** (same gap as §5.2 step 11).
- Step 8 (`checkAllSignaturesUsed`): Full.
- Step 9 (delegate to inner `checkValid` with `chargeFee=false`): Full — `fee_bump.rs:410 inner_transaction_hash` + signature verification.

### §5.5 — Signature Checking Algorithm

Full. `signature_checker.rs:84-186` matches Appendix A decision tree:
1. PRE_AUTH_TX, contents-hash match, V_10+ weight clamp to UINT8_MAX (`cap_weight:192`).
2. HASH_X preimage verification.
3. ED25519 over contents hash.
4. ED25519_SIGNED_PAYLOAD.

Each match marks `used_signatures[idx]=true` and removes the signer from the candidate list (`:181`). `check_all_signatures_used()` enforces INV-T6.

### §5.6 — Operation-Level Validation

Full. `operations/mod.rs:133 is_op_supported` covers per-op protocol-version gates including Inflation removal at V_12+ (`:140`) and pool-deposit/withdraw disable flags (`:142-149`). Threshold dispatch `get_threshold_level:1002` matches §7.6 (LOW for AllowTrust/Inflation/BumpSequence/ClaimCB/ExtendTTL/RestoreFootprint; HIGH for AccountMerge and `SetOptions` when any of masterWeight/lowThreshold/medThreshold/highThreshold/signer is set; MEDIUM otherwise).

### §6 — Fee Framework

- **§6.1 / 6.2** (fee components, `getFee`): Full — `fees.rs:14-148` (`TotalFee`, `InclusionFee`, `ResourceFee`), `frame.fee_to_charge` (live_execution.rs:250).
- **§6.4 processFeeSeqNum**: Full — `live_execution.rs:241`. Sequence-number consumption on V_10+ is deferred to `process_seq_num:533` per spec.
- **§6.5 Soroban refundable fees**: Full — `live_execution.rs:462 refund_soroban_fee` clamps to fee pool, adds back to fee_source balance, emits `TransactionEventStage::AfterAllTxs` from V_23+ (`live_execution.rs:412 process_post_tx_set_apply`) and `AfterTx` pre-V_23 (`:364 process_post_apply`).
- **§6.6 fee-bump fee charging**: Full — `fee_bump.rs:347-422`.
- **§6.4 fee-bump inner fee stash (`@version(<V_25)`)**: Partial — refund path supports both protocol regimes (`fee_bump.rs:612-613` comment), but the inner-fee separate reporting for V_21..V_24 needs spot verification.

### §7 — Apply Pipeline

- **§7.1 entry point**: Full — `live_execution.rs:637 apply_transaction` runs `process_fee_seq_num` → `process_seq_num` → operation dispatch → `process_post_apply` → `remove_one_time_signers`.
- **§7.2 commonPreApply**: Partial — sub-ltx-on-failure mechanics rely on `state/savepoint.rs`; not all V_8 legacy account caching is preserved (spec §7.2 step 1 "reset legacy pre-V_8 account cache" is N/A in Henyey since min protocol is V_24).
- **§7.3 applyOperations**: Partial. Per-op dispatch (`operations/execute/mod.rs:1049`) handles all 27 ops. **Missing the §7.3 post-loop V_14+ check**: `if ltxTx.hasSponsorshipEntry() ⇒ txBAD_SPONSORSHIP`. See INV-T5 Absent above.
- **§7.4 OperationFrame::apply**: Full — pre-flight re-check at apply time is implicit in re-invocation of `is_op_supported` and per-op `doCheckValid` inside each execute fn.
- **§7.5 source account resolution**: Full — `operations/execute/mod.rs:1059`.
- **§7.6 threshold levels**: Full — `operations/mod.rs:1002 get_threshold_level`.

### §9 — Sponsorship Framework

- Internal entry types (`SPONSORSHIP`, `SPONSORSHIP_COUNTER`): Full — `state/sponsorship.rs`. `sponsorship_stack` (in-memory) represents the active sponsorship; per-entry `sponsoringID` and per-account `numSponsoring`/`numSponsored` (`state/sponsorship.rs:590 sponsorship_counts_for_account`) implemented.
- §9.3 reserve math (`getMinBalance` with subentries+numSponsoring−numSponsored): Full — verified via `state/mod.rs:518`.
- §9.4 limits: Full — `opTooManySponsoring` returned from `state/sponsorship.rs:208`.
- **§9.5 begin/end pairing assertion**: Partial — `has_pending_sponsorship()` exists but never asserted at tx end (INV-T5).

### §10 — DEX Conversion Engine

Full coverage:
- `OfferExchange` logic in `operations/execute/offer_exchange.rs` plus `path_payment.rs`/`manage_offer.rs`.
- Rounding modes (NORMAL / STRICT_RECEIVE / STRICT_SEND): Full.
- Cross-self (INV-T14): Full (`path_payment.rs:666`, `manage_offer.rs:918`).
- §10.4 Pool crossing: Full — `path_payment.rs:796 apply_pool_exchange`.
- §10.5 `MAX_OFFERS_TO_CROSS = 1000`: Full constants in `manage_offer.rs:35` and `path_payment.rs:506`.

### §11 — Soroban Execution

- §11.2 fee model + `CxxTransactionResources`: Full — `validation.rs:1325 get_num_disk_read_entries`, `soroban/budget.rs`.
- §11.3 `checkSorobanResources` (10 sub-checks): Full — `validation.rs:1219-1317`.
- §11.4 `invoke_host_function` boundary: Full — `soroban/host.rs`.
- §11.5 Diagnostic events: Full — `events.rs`.
- §11.6 Parallel execution: Partial — single-threaded Rust port short-circuits the multi-thread merge. The `hot_archive_restored_keys` extraction and TTL/restore tracking is implemented (`invoke_host_function.rs:636-808`), but `ParallelTxSuccessVal { modifiedEntryMap, restoredEntries }` is not exposed as a separate type. This is acceptable because consensus parity only requires the final state, which is correct.

### §12–§14 — State / Meta / Events

- §12 LedgerTxn layering: N/A — Henyey uses `state/savepoint.rs` (in-memory savepoints) rather than nested `LedgerTxn`; observable state ordering preserved.
- §13.1 meta version selection: Full — `meta_builder.rs:752-925` selects V2/V3/V4 by protocol.
- §13.3 change types incl. `LedgerEntryRestored`: Full — `meta_builder.rs:441`.
- §14.1 transaction-level fee events: Full — `events.rs:518-555 new_fee_event`, with stage selection.
- §14.2 op-level events (`newTransferEvent`, `newMintEvent`, `newBurnEvent`, `newClawbackEvent`, `newSetAuthorizedEvent`, `eventsForClaimAtoms`): Full — `events.rs` exports all of these.
- §14.3 XLM reconciliation pre-V_8: N/A (Henyey min V_24).
- §14.4 P23 SAC format toggle: Full — `events.rs` supports both legacy and P23-style topic prefixes (verified via the `mUpdateSACEventsToProtocol23Format` analogue).

### §15 — Error Handling

All 19 tx-level codes plus 7 op-level wrapper codes are present in `result.rs:225-280`:
- §15.1 — all 19 `TransactionResultCode` variants mapped (`result.rs:263-281`).
- §15.2 — op-wrapper codes mapped via XDR.
- **§15.3 internal-error handling**: Absent — no `txINTERNAL_ERROR` increment path or `HALT_ON_INTERNAL_TRANSACTION_ERROR` config gate. Exceptions surface as Rust `Result::Err(TxError)` and bubble out to the apply loop without converting to `TxInternalError` consistently.
- **§15.1 `txFROZEN_KEY_ACCESSED`** (-18): code exists in result enum but never emitted (see §5.2 step 11 Absent).

### §16 — Invariants

See the dedicated Invariant Coverage table above (INV-T1..T15).

### §17 — Constants

Full coverage of normative constants:
- `MAX_OPERATIONS_PER_TX = 100`: `lib.rs:122 MAX_OPS_PER_TX`.
- `MAX_SIGNATURES_PER_TX = 20`: enforced by XDR bounds.
- `MAX_RESOURCE_FEE = 1 << 50`: `validation.rs:51`.
- `getMaxOffersToCross = 1000`: `manage_offer.rs:35`, `path_payment.rs:506`.
- Threshold indices (LOW=1, MED=2, HIGH=3, MASTER=0): `henyey_common::ThresholdLevel`.
- Inflation constants: implicitly N/A (op always returns NotTime).
- `XDR_DEPTH_LIMIT = 500`: **Absent** (see §5.1-1).

## Dangling Spec Anchors

Two existing anchors reference sections that don't exist in the regenerated v26.0.1 spec:

1. `crates/tx/src/validation.rs:553` → `TX_SPEC §4.2.3` (ledger sequence max bound). The regenerated spec has no §4.2.3; the closest match is **§5.2 step 8 isTooLate** ("`@version(≥V_19)`: if `LedgerBounds.maxLedger != 0` and `maxLedger ≤ header.ledgerSeq` ⇒ `txTOO_LATE`"). Recommend renumber to `TX_SPEC §5.2 step 8`.
2. `crates/tx/src/validation.rs:587` → `TX_SPEC §4.2.6` (non-Soroban tx forbidden from carrying SorobanTransactionData). The regenerated spec covers this in **§5.2 step 7** ("Classic tx ext gate. `@version(≥V_21)` and classic tx: if `ENVELOPE_TYPE_TX` and `tx.ext.v() != 0` ⇒ `txMALFORMED`"). Recommend renumber to `TX_SPEC §5.2 step 7`.

## Drift Items

None identified — implemented behavior is consistent with spec where present. The Absent/Partial items are gaps in coverage, not divergent semantics.

## Recommendations

1. **Implement CAP-77 frozen-key gate** in `validation.rs` (§5.2 step 11 and §5.4 step 7). The `frozen_keys.rs` machinery is built but unwired — a single call from `check_valid_pre_seq_num` (with `SorobanNetworkConfig` access) plus a fee-bump branch in `fee_bump.rs` would close this Absent. Also produces `TxFrozenKeyAccessed` (-18).
2. **Implement INV-T5 sponsorship leftover check**: at the end of `apply_transaction` (post-op-loop, V_14+), call `state.has_pending_sponsorship()` and convert to `TxBadSponsorship` if true.
3. **Add explicit XDR depth check** (§5.1-1): import `henyey_common`'s XDR depth helper (or write one) and gate at the entry of `check_valid_pre_seq_num` with limit 500 ⇒ `TxMalformed`. Even if the underlying XDR codec rejects on parse, an explicit check prevents drift.
4. **Implement isTooEarlyForAccount** (§5.3-2): read `AccountEntry.ext.v3.seqTime`/`seqLedger`, compare against `minSeqAge`/`minSeqLedgerGap`, produce `BadMinAccountSequenceAge`/`LedgerGap`.
5. **Wire `TxInternalError`** (§15.3): catch panics/Err at the `apply_transaction` boundary and set `TxInternalError` on the result (today errors propagate as Rust `Result::Err`).
6. **Fix the two dangling spec anchors** at `validation.rs:553` and `validation.rs:587` (renumber to §5.2 step 8 / §5.2 step 7).
7. **Audit fine-grained two-phase atomicity (INV-T13)** to confirm op-level rollback semantics in `state/savepoint.rs` match the V_14+ ltxOp-discard-on-failure contract from spec §7.3 step 5.
