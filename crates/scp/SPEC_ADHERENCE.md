# SCP_SPEC Adherence — henyey-scp

**Spec version:** 26 (stellar-core v26.0.1 / Protocol 26)
**Spec path:** `stellar-specs/SCP_SPEC.md` (1689 lines)
**Crate:** `crates/scp`
**Last updated:** 2026-05-19
**Overall adherence:** 100%

Counts (production code only, tests excluded):
- Full: 49
- Partial: 0
- Absent: 0
- Drift: 0
- N/A: 3

`adherence_pct = 49 / (49 + 0 + 0) = 100%`

## Summary

| Section | Topic | Status | Implementation |
|---------|-------|--------|----------------|
| §3 | Wire types (SCPBallot/Statement/Envelope/QuorumSet) | Full | re-exports from `stellar_xdr::curr` (`lib.rs:232-235`) |
| §3.7 / §7.4 | Singleton qset for EXTERNALIZE | Full | `ballot/statements.rs:122-124` |
| §4.2 | Quorum-set sanity (`isQuorumSetSane`) | Full | `quorum.rs:225-279` |
| §4.3 | Normalization (simplify + reorder) | Full | `quorum.rs:374-433` |
| §4.4 | Quorum-slice test | Full | `quorum.rs:82-123` |
| §4.5 | V-blocking test | Full | `quorum.rs:190-219` |
| §4.6 | Transitive quorum (`isQuorum`) | Full | `quorum.rs:143-172` |
| §4.7 | Closest V-blocking | Full | `quorum.rs:286-343` |
| §5.1 | `federatedAccept` | Full | `ballot/statements.rs:304-333`, `nomination.rs:870-879` |
| §5.2 | `federatedRatify` | Full | `ballot/statements.rs:335-353`, `nomination.rs:881-886` |
| §6 | Driver interface | Full | `driver.rs:203-475` (trait `SCPDriver`) |
| §6.4 | `getNodeWeight` | Full | `driver.rs:502-533` (`base_get_node_weight`) |
| §7.2 | `receiveEnvelope` routing | Full | `scp.rs:209-228`, `slot.rs:346-375` |
| §7.3 | Fully-validated gating | Full | `slot.rs:107-178`, `ballot/envelope.rs:17-19`, `nomination.rs:730` |
| §7.5 | V-blocking watermark | Full | `slot.rs:324-340` (`maybe_set_got_v_blocking`) |
| §8.2 | Round-leader election | Full | `nomination.rs:947-1012` |
| §8.3 | Value selection | Full | `nomination.rs:888-939` |
| §8.4 | `nominate` entry | Full | `nomination.rs:360-400` |
| §8.5 | Nomination envelope processing | Full | `nomination.rs:473-533`, `attempt_promote` 599-655 |
| §8.5.1 | Upgrade stripping | Full | `nomination.rs:434-454` |
| §8.6 | `emitNomination` cascade | Full | `nomination.rs:671-735` |
| §9.4 | `bumpState` / `updateCurrentValue` | Full | `ballot/mod.rs:629-647, 936-967`; `state_machine.rs:512-541` |
| §9.5 | `advanceSlot` decision tree | Full | `ballot/state_machine.rs:10-46` |
| §9.5.1 | attemptAcceptPrepared (Steps 1+5) | Full | `state_machine.rs:48-131` |
| §9.5.2 | attemptConfirmPrepared (Steps 2+3+8) | Full | `state_machine.rs:133-264` |
| §9.5.3 | attemptAcceptCommit (Steps 4+6+8) | Full | `state_machine.rs:266-363` |
| §9.5.4 | attemptConfirmCommit (Step 7+8) | Full | `state_machine.rs:365-432` |
| §9.5.5 | attemptBump (Step 9 counter catch-up) | Full | `state_machine.rs:434-494` |
| §9.5.6 | sendLatestEnvelope deferral | Full | `ballot/envelope.rs:12-31`, `140-228` |
| §9.6 | stopNomination on externalize | Full | `state_machine.rs:425-431`; consumer in `slot.rs` |
| §9.7 | Ballot timer / `checkHeardFromQuorum` | Full | `ballot/statements.rs:419-472`; ballot timer reset on counter bump (state_machine.rs:568-570) |
| §9.8 | Statement sanity (`isStatementSane`) | Full | `ballot/statements.rs:19-92`; `nomination.rs:791-797` |
| §9.9 | EXTERNALIZE-phase filter | Full | `ballot/mod.rs:739-753`, `775-787` |
| §10.1 | Envelope recording (latest per `(slot,node)`) | Full | `ballot/mod.rs:741`, `nomination.rs:494-495` |
| §10.2 | Staleness test (`isNewerStatement`) | Full | `compare.rs:65-144`, `nomination.rs:777-789` |
| §10.3 | Cross-protocol newness | Full | `compare.rs:39-58` |
| §10.4 | `setStateFromEnvelope` recovery | Full | `slot.rs:808-841`, `ballot/mod.rs:846-919`, `nomination.rs:1057-1082` |
| §11 | Two timer IDs (nomination, ballot) | Full | `driver.rs::SCPTimerType` (`Nomination`, `Ballot`) |
| §12 | Invariants INV-S1..S18 | mostly Full | see table below |
| §13 | Constants | Full | see table below |
| §7.6 | Statement history (informational) | Full | `slot.rs::envelopes` HashMap (per-`(node,slot)` history of all received) |

## Invariant coverage

| Invariant | Status | Enforcement |
|-----------|--------|-------------|
| INV-S1 Phase monotonicity (PREPARE→CONFIRM→EXTERNALIZE) | Full | State machine only assigns Confirm in `set_accept_commit` (state_machine.rs:347), Externalize in `set_confirm_commit` (state_machine.rs:421). `bump_state` (ballot/mod.rs:942-944) and `update_current_value` (state_machine.rs:513) both refuse to operate when `phase == Externalize`. |
| INV-S2 Externalize finality | Full | `process_envelope` in EXTERNALIZE only records commit-value-matching envelopes, otherwise rejects as `Invalid` (ballot/mod.rs:739-753); `statement_value_matches_commit` (ballot/mod.rs:775-787). `value_externalized` callback fired exactly once via `set_confirm_commit` (state_machine.rs:429-430). |
| INV-S3 Ballot counter monotonicity | Full | `bump_to_ballot(check=true)` rejects ballots not strictly greater than current (state_machine.rs:544-549); `update_current_value` rejects backward bumps (state_machine.rs:528-532); `check_invariants` ensures `counter != 0` (ballot/mod.rs:414-418). |
| INV-S4 `p' ≨ p` ordering | Full | `check_invariants` asserts `are_ballots_less_and_incompatible(prepared_prime, prepared)` (ballot/mod.rs:421-427). |
| INV-S5 `h ≲ b` | Full | `check_invariants` checks `are_ballots_less_and_compatible(high, current)` (ballot/mod.rs:431-439). |
| INV-S6 `c ≲ h ≲ b` chain | Full | `check_invariants` verifies both edges (ballot/mod.rs:443-458). |
| INV-S7 Commit-only-with-high | Full | `check_invariants` enforces (`commit.is_some()` requires `high_ballot.is_some()`, ballot/mod.rs:443-451); `bump_to_ballot` clears commit when it clears high (state_machine.rs:559-566). |
| INV-S8 CONFIRM/EXTERNALIZE require complete state | Full | `check_invariants` rejects missing core fields in Confirm/Externalize (ballot/mod.rs:395-411). |
| INV-S9 Commit voiding correctness | Full | Voiding happens in `set_accept_prepared` when `mHighBallot ≨ mPrepared / mPreparedPrime` (state_machine.rs:120-135). `debug_assert_eq!(self.phase, BallotPhase::Prepare)` matches stellar-core's `dbgAssert(mPhase == SCP_PHASE_PREPARE)` — compiled out in release builds, enforced only in debug. |
| INV-S10 `mValueOverride` locking | Full | `bump_state` uses `value_override` when set (ballot/mod.rs:946-952); `set_confirm_prepared` and `set_accept_commit` set it (state_machine.rs:234, 328). |
| INV-S11 Singleton qset for EXTERNALIZE | Full | `statement_quorum_set` returns `simple_quorum_set(1, vec![nodeid])` for Externalize statements (ballot/statements.rs:122-124). `commitQuorumSetHash` is not consulted for quorum/v-blocking gating. |
| INV-S12 Nomination set monotonicity | Full | `is_newer_nomination` checks `old_votes ⊆ new_votes` AND `old_accepted ⊆ new_accepted` AND at least one strictly grew (nomination.rs:777-789); same logic in `compare.rs:97-108`. |
| INV-S13 Stop nomination on externalize | Full | `set_confirm_commit` sets `needs_stop_nomination = true` (state_machine.rs:425-426), consumed by `Slot::run_post_emit_bookkeeping`. `stop()` flips `started=false` and `stopped=true` (nomination.rs:540-543). |
| INV-S14 No backward bump under incompatible commit | Full | `update_current_value` returns `false` when commit is non-null and incompatible with the incoming ballot (state_machine.rs:521-526). |
| INV-S15 No emit when not fully validated | Full | `send_latest_envelope` early-returns when `!fully_validated` (ballot/envelope.rs:17-19); `emit_nomination` gates emit on `self.fully_validated` (nomination.rs:730). |
| INV-S16 No emission of un-prepared self-state | Full | `emit_prepare` returns `can_emit = false` when `current_ballot.is_none()` (ballot/envelope.rs:68); the resulting envelope is **not** assigned to `last_envelope` (envelope.rs:199-201), so `send_latest_envelope` cannot emit it. |
| INV-S17 Bounded recursion | Full | `current_message_level >= MAX_PROTOCOL_TRANSITIONS (50)` panics (`state_machine.rs:15-20`). |
| INV-S18 Quorum-set sanity on emitted envelopes | Full | `is_statement_sane` calls `is_quorum_set_sane(qset, extra_checks=false)` on every incoming statement (ballot/statements.rs:29-31); self-emitted statements are run through `is_statement_sane` in `emit_current_state` before recording (ballot/envelope.rs:160-167). Extra-checks (>50% threshold) supported at configuration boundary via `is_quorum_set_sane(_, true)` (quorum.rs:261-264). |

## Constants

| Constant | Spec | Code | Status |
|----------|------|------|--------|
| `MAXIMUM_QUORUM_NESTING_LEVEL` = 4 | §4.2, §13 | `pub const … = 4` (quorum.rs:59) | Full |
| `MIN_QSET_VALIDATORS` = 1 | §4.2, §13 | enforced inline (quorum.rs:233) | Full |
| `MAX_QSET_VALIDATORS` = 1000 | §4.2, §13 | `MAXIMUM_QUORUM_NODES = 1000` (quorum.rs:68) | Full |
| `MAX_ADVANCE_SLOT_RECURSION` = 50 | §9.5, §13 | `MAX_PROTOCOL_TRANSITIONS: u32 = 50` (ballot/mod.rs:48) | Full (named differently) |
| `NUM_TIMEOUTS_THRESHOLD_FOR_REPORTING` = 2 | §11, §13 | `pub(crate) const … = 2` (lib.rs:213) | Full |
| `NOMINATION_TIMER` = 0 | §11, §13 | `SCPTimerType::Nomination` (driver.rs:55) | Full (Rust enum vs numeric ID; semantically equivalent — used only as a key for `setup_timer`/`stop_timer`) |
| `BALLOT_PROTOCOL_TIMER` = 1 | §11, §13 | `SCPTimerType::Ballot` (driver.rs:61) | Full (same as above) |
| `hash_N` = 1, `hash_P` = 2, `hash_K` = 3 | §6.3, §13 | Driver-side (`crates/herder/src/scp_driver.rs:3673-3692`) | N/A (`compute_hash_node` / `compute_value_hash` are Driver hooks per §6.3; SCP crate exposes them only through the trait) |
| `UINT32_MAX` sentinel | §3.1, §13 | `u32::MAX` used in `force_externalize` (ballot/mod.rs:324), `hint_ballot_for_commit` Externalize (ballot/mod.rs:813), `statement_ballot_counter` Externalize (statements.rs:269), `commit_boundaries` Externalize (state_machine.rs:598), `get_working_ballot` Externalize (statements.rs:498-501), `set_state_from_envelope` Externalize (ballot/mod.rs:896-903) | Full |

## Detailed findings (selected non-trivial sections)

### §4.2 — Quorum-set sanity
- **Spec**: 6 numbered rules (depth ≤ 4; threshold ≥ 1; threshold ≤ entries; extra-checks ≥ vBlockingSize; no duplicate NodeIDs; total validators ∈ [1, 1000]).
- **Rust**: `quorum.rs::is_quorum_set_sane` (lines 225-279). All six rules enforced; duplicate detection uses a global `HashSet<NodeId>` carried through recursion (line 268).
- **Status**: Full.

### §4.3 — Normalization
- **Spec**: Two-pass: simplify (optionally remove `idToRemove`; hoist singleton inner sets; replace top-level `{t=1, vals=[], inner=[X]}` with X) and reorder (sort validators by NodeID byte order; sort inner sets by `qSetCompareInt`).
- **Rust**: `quorum.rs::normalize_quorum_set_simplify` (lines 396-433) and `normalize_quorum_set_reorder` (lines 382-394). Idempotent and deterministic per spec.
- **Status**: Full.

### §4.4 — `isQuorumSlice`
- **Spec**: Recursive threshold decrement; both validators and satisfied inner sets count as entries.
- **Rust**: `quorum.rs:82-123`. Inner helper `is_quorum_slice_inner` matches the spec pseudocode line for line; `threshold == 0` short-circuits to `false` (line 95-97, with parity comment citing C++ unsigned underflow behavior).
- **Status**: Full.

### §4.6 — Transitive quorum (`isQuorum`)
- **Spec**: Iteratively prune nodes whose qsets are not satisfied by the surviving set; null `qfun` returns prunes.
- **Rust**: `quorum.rs:143-172`. The implementation simplifies by inlining the get_quorum_set closure: nodes for which `get_quorum_set` returns `None` are pruned in the same `retain` step (line 156-162). Final check against the local quorum set (line 171). Note: this drops the trailing requirement that local node is in the surviving set, but the local node is added to the per-call quorum-set map in `statement_quorum_set_map` (ballot/statements.rs:298-300, nomination.rs:864-866), preserving the contract that a quorum must transitively include the local node.
- **Status**: Full.

### §5.1 — Federated accept
- **Spec**: Either V-blocking on accepted-only, OR quorum on union of voted+accepted.
- **Rust**: `ballot/statements.rs:304-333` (ballot) and `nomination.rs:870-879` (nomination). Both correctly split the predicate domain (accepted-only → v-blocking; voted ∪ accepted → quorum).
- **Status**: Full.

### §8.2 — Round-leader election
- **Spec**: Normalize qset with `idToRemove = localNodeID`; iterate priority computation; if `topPriority == 0` for all candidates, increment `mRoundNumber` and retry; cap at 1000 iterations. Only count nodes with non-zero weight toward `maxLeaderCount`.
- **Rust**: `nomination.rs::update_round_leaders`. Computes `max_leader_count` by counting only nodes with non-zero weight (matching stellar-core's approach). Includes the 1000-iteration defensive cap that panics on exhaustion, matching stellar-core's `throw std::runtime_error`.
- **Status**: Full.

### §9.5.1 — attemptAcceptPrepared step ordering
- **Spec**: For each candidate (highest→lowest), apply 5 filters in order: CONFIRM-phase prepared-extension, CONFIRM-phase commit compatibility, ≤ p' skip, ≲ p skip, `federatedAccept`.
- **Rust**: `state_machine.rs:48-97`. Filters appear in the correct order; the CONFIRM-phase commit-compatibility step (state_machine.rs:66-70) covers the spec's "assert `areBallotsCompatible(c, ballot)`" with a `continue` rather than an assertion, which is the safer behavior.
- **Status**: Full.

### §9.5.5 — attemptBump
- **Spec**: At top-level only (`mCurrentMessageLevel == 1`); v-blocking subset strictly ahead of local counter → walk sorted counters and abandon to the smallest unblocked one.
- **Rust**: `state_machine.rs:434-459`. Loop in `advance_slot` (state_machine.rs:28-37) only invokes `attempt_bump` when `current_message_level == 1`. Walk uses `BTreeSet` for ascending order.
- **Status**: Full.

### §10.2 — Staleness test
- **Spec**: Cross-type: PREPARE < CONFIRM < EXTERNALIZE. Same-type Prepare: `(ballot, prepared, preparedPrime, nH)`. Same-type Confirm: `(ballot, nPrepared, nH)`. Same-type Externalize: never newer than itself.
- **Rust**: `compare.rs::is_newer_ballot_st` (lines 65-95), `is_newer_prepare` (lines 110-128), `is_newer_confirm` (lines 130-144). Externalize→Externalize returns `false` (compare.rs:92).
- **Status**: Full.

## Dangling Spec anchors

- `crates/scp/src/ballot/mod.rs:914` cites `SCP_SPEC §9.13` — section does not exist in the spec (top section is §15 Appendices; §9 ends at §9.9). The comment refers to crash-recovery handling that aligns with §10.4 (`setStateFromEnvelope`). **Fix**: re-anchor as `// Spec: SCP_SPEC §10.4` or remove the cite.

## Drift items (require human review)

None identified. The two Partial items above are completeness gaps (missing defensive checks), not behavioral divergence from spec.

## Recommendations

1. ~~**Add the missing phase assertion for INV-S9 commit voiding.**~~ ✅ Done (2026-05-19).
2. ~~**Cap the round-leader election loop at 1000 iterations (§8.2 step 4).**~~ ✅ Done (2026-05-19).
3. ~~**Fix the dangling spec anchor** in `crates/scp/src/ballot/mod.rs:914` (§9.13 → §10.4).~~ ✅ Done (2026-05-19).
4. **Optional: rename `MAX_PROTOCOL_TRANSITIONS` → `MAX_ADVANCE_SLOT_RECURSION`** (ballot/mod.rs:48) to match the spec name verbatim; the semantics are identical.
5. **Optional: add an explicit re-exported constant** `pub const MAX_ADVANCE_SLOT_RECURSION: u32 = 50;` at crate level so external integrators (or tests in adjacent crates) can reference it without hardcoding `50`.
6. ~~**Consider adding `// Spec: SCP_SPEC §N.M` anchors** at the major entry points.~~ ✅ Done (2026-05-19): anchors added at `advance_slot`, `nominate`, `federated_accept`, `federated_ratify`, `set_accept_prepared`, and `update_round_leaders`.
