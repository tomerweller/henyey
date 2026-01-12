# Known Issues

This document tracks known issues in rs-stellar-core that affect network synchronization and consensus participation.

## 1. Buffered Gap After Catchup (Critical)

**Status:** Unresolved
**Severity:** Critical - Prevents real-time sync
**Component:** Catchup / Herder
**Last Verified:** 2026-01-11 - Observed on fresh testnet run

### Description
After catchup completes to a checkpoint ledger, the node cannot close subsequent ledgers because the required transaction sets (tx_sets) are no longer available from peers.

### Symptoms
- Node stuck at checkpoint+1 ledger (e.g., `current_ledger=430400`, `first_buffered=430401`)
- Continuous "DontHave for TxSet" messages from peers
- Buffer keeps growing while the gap remains
- Repeated catchup attempts that skip because target is already past

### Root Cause
1. Catchup completes to checkpoint ledger N (e.g., 430399)
2. Node advances to ledger N+1 (e.g., 430400)
3. To close ledger N+2 (e.g., 430401), node needs its tx_set
4. Node requests tx_set from peers
5. Peers respond "DontHave" - tx_set is too old (peers only keep ~12 recent slots)
6. Without tx_set, ledger cannot close
7. Catchup system detects gap, tries to catchup to latest checkpoint
8. Latest checkpoint <= current ledger, so catchup is skipped
9. Cycle repeats indefinitely

### Example Log Pattern
```
INFO  Evaluating buffered catchup current_ledger=430400 first_buffered=430401 last_buffered=430446
WARN  Buffered catchup stuck timeout; triggering catchup
INFO  Already at or past target; skipping catchup current_ledger=430400 target_ledger=430399
INFO  Peer reported DontHave for TxSet hash="fdd5aa743a41..."
```

### Potential Fixes
1. Implement ledger replay from history archive (fetch tx_sets from archive, not peers)
2. Fast-forward past the gap using EXTERNALIZE messages when tx_sets are unavailable
3. Catch up to a future checkpoint instead of the latest available one

---

## 2. Ledger Header Hash Mismatch (Critical - Unresolved)

**Status:** Unresolved - snap() fix was partial, additional bugs remain
**Severity:** Critical - Prevents ledger closing
**Component:** Ledger Manager / Bucket List / Header Computation
**First Observed:** 2026-01-11
**Last Verified:** 2026-01-11 - Still occurring after snap() fix

### Description
After catching up from history archives, the node's locally computed ledger header hash does not match the network's expected `prev_ledger_hash`. This prevents the node from closing new ledgers and participating in consensus.

### Latest Test Results (2026-01-11)
```
INFO  Ledger manager initialized from catchup ledger_seq=434751
INFO  Evaluating buffered catchup current_ledger=434752 first_buffered=434753
ERROR Hash mismatch - our computed header hash differs from network's prev_ledger_hash
      current_seq=434752 close_seq=434753
      our_hash=6d7c70ea089bfff9d1be0c82d1a8d28a68f7d75544ed1d95e6f37c7973a36a20
      network_prev_hash=23eb28d09dd5cfcecc9bc1fb80a26195c00fa468a1529e1c46b3954c67ad1607
```

### Investigation Progress

**P23+ Soroban Fee Refunds (Commit 5648f8e):** Added post-transaction refund processing for Protocol 23+, matching C++ stellar-core's `processPostTxSetApply()`. However, the hash mismatch still occurs even for ledgers with NO Soroban transactions with refunds, indicating this was not the root cause.

**Enhanced verify-execution Tool (Commit 3a92735):** Added header hash verification to verify-execution tool. The tool now compares bucket_list_hash, fee_pool, tx_result_hash, and overall header_hash against CDP expected values.

**restart_merges Implementation (2026-01-11):** After restoring bucket list from HAS, we now call `restart_merges()` to recreate pending merges that should have been in progress at the checkpoint. This matches C++ stellar-core's `BucketListBase::restartMerges()`. **Result:** Bucket levels 1+ now have non-empty curr buckets after catchup (they were previously empty). However, the hash still doesn't match - the merge results themselves differ from C++.

### ROOT CAUSE IDENTIFIED: Bucket List snap() Bug

**Key Finding:** The `BucketLevel::snap()` method was returning the WRONG bucket.

**Bug:** In C++ stellar-core, `snap()` does:
1. `mSnap = mCurr` (copy curr to snap)
2. `mCurr = empty`
3. `return mSnap` (return the NEW snap, which was the old curr)

Our Rust implementation was incorrectly:
1. Save old snap
2. Move curr to snap
3. Return the OLD snap (**WRONG**)

This caused the wrong bucket to be merged into the next level during spills, leading to hash divergence.

**Fix (2026-01-11):** Fixed `snap()` in both `bucket_list.rs` and `hot_archive.rs` to return `self.snap.clone()` after the assignment, matching C++ behavior.

### Verification Status

**PARTIALLY FIXED (2026-01-12):** The bucket list restoration from HAS is now verified correct. Multiple fixes have been applied:

1. **snap() fix:** Fixed the bucket level snap() method to return the correct bucket
2. **restart_merges fix:** Added restart_merges() to recreate pending merges after HAS restore
3. **Hot archive add_batch:** Added hot archive bucket list updates during verify-execution

**Verified correct (2026-01-12):**
- **HAS restore is correct:** The bucket list hash computed from HAS buckets at checkpoint 379903 matches the expected hash in the ledger header:
  - Expected (from ledger header): `c1360254031d14858d00c48fc5cae3eb90b140be31094088c3dab41fe159c8e6`
  - Computed (live + hot archive combined): `c1360254031d14858d00c48fc5cae3eb90b140be31094088c3dab41fe159c8e6` ✓
- **restart_merges is correct:** The pending merges are correctly recreated using the right inputs (prev level's snap, with correct shouldMergeWithEmptyCurr)
- **Merge order is correct:** The merge uses old_bucket=curr, new_bucket=snap, matching C++ behavior

**Fixed (2026-01-12): Incorrect INIT→LIVE Normalization**

Root cause identified and fixed: The Rust bucket merge code was incorrectly converting INIT entries to LIVE entries during merges at level 10 (the highest level). This was based on a misunderstanding of C++ stellar-core's behavior.

**Bug:** The Rust code set `normalize_init = !keep_dead`, meaning at level 10 (where `keep_dead = false`), all INIT entries were converted to LIVE entries during merge.

**C++ Behavior:** In C++ stellar-core, `keepTombstoneEntries` ONLY controls whether DEAD entries are kept or filtered out in `BucketOutputIterator::put()`. It does NOT affect INIT entries at all. The function `isTombstoneEntry()` returns `true` only for `DEADENTRY`, not for `INITENTRY`.

**Fix:** Changed `normalize_init` to always be `false` in both `add_batch_internal()` and `restart_merges()`. INIT entries now remain as INIT entries at all bucket levels, matching C++ behavior.

**Files Modified:**
- `crates/stellar-core-bucket/src/bucket_list.rs` - Fixed `normalize_init = false` in two locations

**Verification:** All 117 bucket tests pass after the fix.

**Live Bucket List Now Works (2026-01-12):**

Tested with `replay-bucket-list --live-only` which verifies only the live bucket list hash:
- **Result:** 0 mismatches across all tested ledgers
- This confirms the live bucket list implementation is now correct

The remaining issue is with the **hot archive bucket list**. Hot archive entry extraction has been implemented but the combined hash still doesn't match:

**Implemented (2026-01-12):**
1. Added `extract_restored_keys()` function to cdp.rs - extracts keys from `LedgerEntryChange::Restored` entries in transaction meta
2. Before processing evicted keys, we look up full entry data from the bucket list for persistent entries
3. Pass archived_entries and restored_keys to `hot_archive.add_batch()` during replay
4. Exported `is_persistent_entry` from stellar-core-bucket for use in main.rs

**Current Status:**
- Live bucket list hash shows 0 mismatches in live-only mode
- **Initial state at checkpoint IS CORRECT** - verified against checkpoint header hash
- Hot archive hash changes after first ledger but then stays constant
- Combined hash diverges from expected starting at first ledger after checkpoint

**Key Finding (2026-01-12):**
The initial state at checkpoint (e.g., 379967) matches the expected hash from the header:
```
Verifying initial state at checkpoint 379967...
  Checkpoint 379967: INITIAL STATE OK
```
This confirms:
1. Bucket restoration from HAS works correctly
2. restart_merges implementation is correct
3. The combined hash (SHA256(live || hot_archive)) matches at checkpoint time

The hash divergence occurs when processing the FIRST ledger after checkpoint (e.g., 380000),
not during restoration. Investigation ongoing.

**Fix Applied (2026-01-12): Hot Archive Metadata Extension**

Fixed the `BucketMetadataExt` in hot archive bucket creation. C++ uses V1 extension with `BucketListType::HotArchive`, but our Rust code was using V0:

**Bug:** Our Rust code used:
```rust
ext: BucketMetadataExt::V0,
```

**Fix:** Changed to match C++:
```rust
ext: BucketMetadataExt::V1(BucketListType::HotArchive),
```

**Files Modified:**
- `crates/stellar-core-bucket/src/hot_archive.rs` - Fixed in `fresh()` and `merge_hot_archive_buckets()`

**Status:** Multiple fixes applied but issue persists. The hot archive hash still diverges after the first ledger.

**Fix Applied (2026-01-12): Empty Bucket Handling**

Fixed `add_batch` to always call `HotArchiveBucket::fresh()` even when there are no entries.

**Bug:** When no archived entries or restored keys, we created an empty bucket with no entries:
```rust
let new_bucket = if !has_entries {
    HotArchiveBucket::empty()  // hash = 0, no metadata
} else { ... }
```

**Fix:** Always create a fresh bucket with metadata:
```rust
let new_bucket = HotArchiveBucket::fresh(protocol_version, archived_entries, restored_keys)?;
```

This matches C++ behavior where `HotArchiveBucket::fresh()` is always called, creating a bucket with at least a metadata entry.

**Current Status:**
- Both V1 metadata and empty bucket fixes have been applied
- Hot archive hash still diverges after first ledger
- Initial state at checkpoint IS CORRECT
- Live bucket list works correctly (0 mismatches in live-only mode)

**Observations:**
- Evictions at ledger 379965 archive 3 entries into hot archive
- Hot archive hash changes from initial `464dd144...` to `80821fbe...` after processing
- Expected combined hash at 379967: `dfd52ae9...`, got: `4a15b298...`

**Extensive Investigation (2026-01-12):**

1. **Hash computation with XDR record marks (Fixed):** C++ bucket hash includes 4-byte XDR record marks (size prefix with high bit set) for each entry. Fixed `compute_hash()` to include record marks.

2. **Entry order preservation (Fixed):** C++ bucket files have entries in semantic order (using LedgerEntryIdCmp), not XDR byte order. Added `ordered_entries` Vec to preserve file order for loaded buckets and implemented C++ comparison function for fresh buckets.

3. **Metadata version in fresh buckets (Fixed):** C++ HotArchiveBucketList::addBatch uses `mLedger` (previous ledger seq) as the protocol version for fresh buckets, not the actual protocol version. Fixed to match.

4. **Round-trip hash verification:** After fixing entry ordering, loaded buckets now have matching hashes when recomputed. No more round-trip mismatch warnings.

**C++ Comparison Implementation:** Added `compare_hot_archive_entries()` and supporting functions that match C++ `BucketEntryIdCmp`:
- Metadata entries sort first
- Other entries compared by LedgerKey using `compare_ledger_keys()`
- CONTRACT_DATA compared by: contract (ScAddress), key (ScVal), durability
- ScAddress and ScVal compared using XDR byte comparison for complex types

**Remaining Issue:** Fresh bucket hashes still differ from C++. Possible causes:
1. Subtle difference in comparison order for specific ScVal types
2. Difference in how entries are extracted/serialized before sorting
3. Something different about how C++ processes the same entries

The issue requires deeper debugging with actual entry-level comparison to identify why our sorted order differs from C++'s.

### Symptoms
- Node catches up successfully to a checkpoint ledger
- Node may close 1 ledger successfully after catchup
- Hash mismatch error occurs when attempting to close subsequent ledgers
- Repeated ERROR logs: "Hash mismatch - our computed header hash differs from network's prev_ledger_hash"
- Node clears buffered ledgers and may trigger re-catchup
- Node state shows "Synced" but cannot advance ledgers

### Example Log Pattern
```
ERROR Hash mismatch - our computed header hash differs from network's prev_ledger_hash
      current_seq=432512 close_seq=432513
      our_hash=33cc2081dafcb857bf397fe67aa967bada5f14d3f1d60e2d3d33a6dce322cb47
      network_prev_hash=90f6e2ce99bf44f1cb9b966ab9ecf3be5660cc24c4d274312781ad64d9b2c155
      header_version=25
      header_bucket_list_hash=2854f44500d9400832aee9e63ede64401a7899c1d90490702063b47a0f686610
      header_tx_result_hash=74ae054c8f35c9ad2f7b960401ea316b3599b9a0e8dbaf2d07270cf464abf6de
      header_total_coins=1000000000000000000
      header_fee_pool=67689576225
      header_close_time=1768156899
      header_tx_set_hash=9a32a70d3195e3ce797952e0e912cf4583be56495550af3485343a81630a5a3b
      header_upgrades_count=0

ERROR Failed to apply buffered ledger ledger_seq=432513
      error=internal error: Failed to begin close: ledger hash mismatch

WARN  Hash mismatch detected - cleared all buffered ledgers, will trigger catchup
```

### Root Cause Analysis
The ledger header hash is computed from multiple components:
1. `ledgerVersion` - Protocol version
2. `previousLedgerHash` - Hash of prior ledger header
3. `scpValue` - SCP consensus value (close time, tx set hash, upgrades)
4. `txSetResultHash` - Merkle root of transaction results
5. `bucketListHash` - Hash of the bucket list state
6. `ledgerSeq` - Ledger sequence number
7. `totalCoins` - Total lumens in existence
8. `feePool` - Accumulated fees
9. `inflationSeq` - Inflation sequence (deprecated)
10. `idPool` - ID pool counter
11. `baseFee` / `baseReserve` - Network parameters
12. `maxTxSetSize` - Max transactions per ledger
13. `skipList` - Recent header hashes for verification

Potential sources of divergence:
- **Bucket list hash mismatch**: State from catchup may differ from network state due to:
  - Incorrect bucket application order
  - Missing or incorrect handling of DEADENTRY markers
  - Hot archive bucket state divergence
- **Transaction result hash mismatch**: Transaction execution produces different results:
  - Fee calculation differences
  - Operation result encoding differences
  - State changes not matching C++ stellar-core
- **Fee pool divergence**: Accumulated fees computed differently
- **Protocol upgrade handling**: Upgrade application timing/logic differs

### Investigation Steps
1. Compare bucket list hash at catchup checkpoint vs network expectation
2. Verify transaction execution parity with C++ stellar-core for specific ledger
3. Check fee calculation and accumulation logic
4. Verify ledger header XDR serialization matches upstream format

### Related Files
- `crates/stellar-core-ledger/src/manager.rs` - Ledger header computation
- `crates/stellar-core-ledger/src/header.rs` - Header hash calculation
- `crates/stellar-core-bucket/` - Bucket list management
- `crates/stellar-core-tx/` - Transaction execution

---

## 3. Auth Sequence Errors with Peers (Resolved)

**Status:** Resolved
**Severity:** Medium - Caused peer disconnections
**Component:** Overlay

### Description
Peers disconnected with "unexpected auth sequence" errors shortly after authentication.

### Resolution
Fixed in auth.rs codec improvements. The issue was related to MAC computation and sequence number handling in the overlay authentication protocol.

### Previous Symptoms
- Peer authenticates successfully
- Within seconds, peer sends ERROR with "unexpected auth sequence"
- Peer disconnects

### Verification
As of 2026-01-11, testnet connections show stable peer connectivity with 3 peers and no auth sequence errors. SCP envelopes are being processed as valid from all connected validators.

---

## 4. Out-of-Sync Peer Disconnections

**Status:** Expected Behavior (consequence of Issue #1)
**Severity:** Low
**Component:** Overlay
**Last Verified:** 2026-01-11 - NOT observed in 10+ minute test session

### Description
Peers disconnect the node with "random disconnect due to out of sync" when the node falls too far behind the network.

### Symptoms
- Peer sends ERROR: `code=Load, msg=random disconnect due to out of sync`
- Happens when node is many ledgers behind

### Root Cause
This is expected C++ stellar-core behavior. Peers disconnect nodes that are significantly behind to avoid wasting resources. This is a consequence of Issue #1, not a separate bug.

### Recent Observations (2026-01-11)
In multiple testnet runs totaling 15+ minutes, this issue was **not observed**:
- Node maintained stable connections to all 3 SDF testnet validators
- No "out of sync" disconnection errors logged
- Peers remained connected despite node being 20-60 ledgers behind due to hash mismatch issue
- Node caught up from checkpoint 433407 to 433472 without peer disconnections

The issue may only manifest when the node falls significantly further behind (100+ ledgers).

---

## 5. heard_from_quorum=false Persistent Warning (Resolved)

**Status:** Resolved
**Severity:** Medium - Indicated consensus issues
**Component:** Herder / SCP / Quorum Tracker
**Resolved:** 2026-01-11

### Description
The node continuously reported that it had not heard from its quorum, even while receiving and processing valid SCP messages from all configured validators.

### Root Cause
Two issues combined to cause this:

1. **Quorum sets stored with wrong node_id**: In `handle_quorum_set`, quorum sets were stored using the `peer_id` (the peer that delivered the message) instead of `envelope.statement.node_id` (the validator who uses that quorum set). This meant `get_quorum_set(validator_id)` returned `None`.

2. **Timing issue**: The heartbeat checked `heard_from_quorum(tracking_slot)`, but at heartbeat time, no SCP envelopes had been received for the current tracking slot yet. Envelopes arrived milliseconds later.

### Solution
1. **Track node_ids per quorum set request**: Modified `PendingQuorumSet` to track which node_ids need each quorum set hash. When the quorum set arrives, it's associated with all requesting node_ids.

2. **Associate quorum sets on every envelope**: When processing SCP envelopes, always call `request_quorum_set(hash, node_id)` which either creates a pending request OR immediately associates an existing quorum set with the node_id.

3. **Check quorum for latest_ext slot**: Changed heartbeat to check `heard_from_quorum(latest_ext)` instead of `tracking_slot`, since we have actual SCP data for externalized slots.

### Verification
After fix, testnet logs show:
```
INFO  Heartbeat tracking_slot=433383 ledger=433343 latest_ext=433382 peers=3 heard_from_quorum=true is_v_blocking=true
```

### Files Modified
- `crates/stellar-core-herder/src/scp_driver.rs` - Added node_id tracking to PendingQuorumSet
- `crates/stellar-core-herder/src/herder.rs` - Updated passthrough methods
- `crates/stellar-core-app/src/app.rs` - Fixed SCP envelope handling and heartbeat slot selection

---

## Recently Fixed Issues

### Missing restart_merges After HAS Restore (Partial Fix)

**Fix:** Implemented `restart_merges()` in `bucket_list.rs` and `hot_archive.rs`, called after restoring from HAS.

When a bucket list is restored from a History Archive State (HAS), any pending merges that should have been in progress at that checkpoint must be recreated. This matches C++ stellar-core's `BucketListBase::restartMerges()`.

**Implementation:**
- For each level > 0 with no pending merge, check if the previous level's snap is non-empty
- If so, calculate when the merge would have started: `roundDown(ledger, levelHalf(i-1))`
- Start a merge using the previous level's snap bucket

**Result:** Bucket levels 1+ now have non-empty curr buckets after catchup (they were previously all zeros). However, the merge results still differ from C++ stellar-core, indicating additional issues in the merge logic.

**Files Modified:**
- `crates/stellar-core-bucket/src/bucket_list.rs` - Added `restart_merges()` method
- `crates/stellar-core-bucket/src/hot_archive.rs` - Added `restart_merges()` method
- `crates/rs-stellar-core/src/main.rs` - Call `restart_merges()` after bucket list restoration

---

### Bucket List snap() Bug (Partial Fix)

**Fix:** Fixed `snap()` in `bucket_list.rs` and `hot_archive.rs` to return new snap instead of old snap

The Rust `BucketLevel::snap()` method was returning the wrong bucket. C++ returns the NEW snap (old curr) but we were returning the OLD snap. This caused wrong bucket to be merged during level spills.

**Status:** This fix was necessary but not sufficient. Issue #2 (hash mismatch) still occurs - there are additional bugs in bucket list handling that need investigation.

---

### Invalid SCP Envelope Warnings After Fast-Forward (Fixed)

**Fix:** Added `force_externalize` to SCP library and call it when fast-forwarding via EXTERNALIZE

When fast-forwarding via EXTERNALIZE messages from the network, the SCP library was not informed about the externalization. Subsequent envelopes for the same slot were marked Invalid because the ballot protocol didn't know the slot was already externalized.

**Root Cause:**
- When receiving EXTERNALIZE for a future slot, the herder recorded the externalization in `scp_driver`
- But the SCP library's slot/ballot state was never updated
- When more envelopes arrived for that slot, the ballot protocol rejected them because values didn't match the (unset) commit value

**Solution:**
- Added `BallotProtocol::force_externalize(value)` to set the ballot to Externalize phase
- Added `Slot::force_externalize(value)` calls the ballot's method
- Herder now calls `scp.force_externalize(slot, value)` when fast-forwarding

---

### SCP Envelope "Too Old" Rejection After Catchup (Fixed)

**Commit:** 632bcba
**Fix:** Added `MAX_SLOTS_TO_REMEMBER = 12` constant and window-based envelope acceptance

After catchup, SCP envelopes within a 12-slot window of the tracking slot are now accepted instead of being rejected as "too old". This matches C++ stellar-core behavior.
