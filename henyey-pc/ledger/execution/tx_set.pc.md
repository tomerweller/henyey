## Pseudocode: crates/ledger/src/execution/tx_set.rs

### execute_transaction_set

```
execute_transaction_set(snapshot, transactions, context, delta, soroban):
  → delegate_to(execute_transaction_set_with_fee_mode,
      ..., deduct_fee=true)
```

**Calls**: [execute_transaction_set_with_fee_mode](#execute_transaction_set_with_fee_mode)

### execute_transaction_set_with_fee_mode

```
execute_transaction_set_with_fee_mode(snapshot, transactions, context,
    delta, soroban, deduct_fee):
  id_pool = snapshot.header.id_pool
  executor = new TransactionExecutor(context, id_pool, soroban.config)
  if soroban.module_cache provided:
    executor.set_module_cache(module_cache)
  if soroban.hot_archive provided:
    executor.set_hot_archive(hot_archive)

  "Load all orderbook offers before executing any transactions"
  executor.load_orderbook_offers(snapshot)

  → run_transactions_on_executor(executor, snapshot,
      transactions, context.base_fee, soroban.base_prng_seed,
      deduct_fee, delta, external_pre_charged=none)
```

**Calls**: [run_transactions_on_executor](#run_transactions_on_executor)

### run_transactions_on_executor

"Core transaction execution loop, separated from executor setup"
"so it can be reused by both free function and persistent executor paths."

```
run_transactions_on_executor(executor, snapshot, transactions,
    base_fee, soroban_base_prng_seed, deduct_fee, delta,
    external_pre_charged):

  --- Phase 1: Prefetch all keys for entire tx set ---
  all_keys = empty set
  for each (tx, _) in transactions:
    frame = new TransactionFrame(tx)
    add frame.keys_for_fee_processing() to all_keys
    add frame.keys_for_apply() to all_keys
  snapshot.prefetch(all_keys)
```

**Calls**: [sub_sha256](signatures.pc.md#sub_sha256) | [build_tx_result_pair](result_mapping.pc.md#build_tx_result_pair)

```
  --- Phase 2: Pre-deduct fees ---
  if external_pre_charged is provided:
    pre_fee_results = external_pre_charged
  else if deduct_fee:
    pre_fee_results = []
    for each (tx, tx_base_fee) in transactions:
      tx_fee = tx_base_fee or base_fee
      (fee_changes, charged_fee)
        = executor.process_fee_only(snapshot, tx, tx_fee)
      append { charged_fee, should_apply=true, fee_changes }
  else:
    pre_fee_results = empty

  --- Phase 3: MAX_SEQ_NUM_TO_APPLY (Protocol 19+) ---
  "When any transaction contains AccountMerge, record max sequence number"
  "per source account to prevent merges allowing sequence-number reuse."
  if deduct_fee:
    merge_seen = false
    acc_to_max_seq = empty map
    for each (tx, _) in transactions:
      source_bytes = tx.source_account key bytes
      seq = tx.sequence_number
      update acc_to_max_seq[source_bytes] = max(existing, seq)
      if any op is AccountMerge: merge_seen = true
    if merge_seen:
      executor.state.set_max_seq_num_to_apply(acc_to_max_seq)

  --- Phase 4: Execute each transaction ---
  for each (tx_index, (tx, tx_base_fee)) in transactions:
    "Flush pending RO TTL bumps for keys in this TX's write footprint"
    if tx has Soroban write footprint:
      executor.state.flush_ro_ttl_bumps_for_write_footprint(keys)

    "Snapshot delta before each TX (preserves prior TX changes)"
    executor.state.snapshot_delta()

    tx_fee = tx_base_fee or base_fee
    tx_prng_seed = sub_sha256(soroban_base_prng_seed, tx_index)

    "Execute with deduct_fee=false — fees already pre-deducted"
    result = executor.execute_transaction_with_fee_mode(
      snapshot, tx, tx_fee, tx_prng_seed, deduct_fee=false)

    tx_result = build_tx_result_pair(frame, network_id, result,
      tx_fee, protocol_version)

    fee_changes = if pre-charged: pre_fee_results[tx_index].fee_changes
                  else: result.fee_changes
    post_fee_changes = result.post_fee_changes

    build TransactionResultMetaV1 {
      result, fee_processing, tx_apply_processing, post_fee_changes }
    collect results, tx_results, tx_result_metas

  --- Phase 5: Protocol 23+ Soroban fee refunds ---
  "Matches stellar-core processPostTxSetApply()"
  if pre-charged:
    for each (idx, (tx, _)) in transactions:
      refund = results[idx].fee_refund
      if refund > 0:
        fee_source_id = fee source account from tx
        executor.state.apply_refund_to_delta(fee_source_id, refund)
        executor.state.delta.add_fee(-refund)

  --- Phase 6: Finalize ---
  executor.state.flush_deferred_ro_ttl_bumps()
  executor.apply_to_delta(snapshot, delta)

  if not external_pre_charged and deduct_fee:
    delta.record_fee_pool_delta(executor.total_fees())

  collect all hot_archive_restored_keys from results

  → TxSetResult { results, tx_results, tx_result_metas,
      id_pool, hot_archive_restored_keys }
```

### execute_soroban_parallel_phase

"Execute full Soroban parallel phase: stages sequentially,"
"clusters within each stage in parallel."

```
execute_soroban_parallel_phase(snapshot, phase, classic_tx_count,
    context, delta, soroban, external_pre_charged):

  "Global TX offset tracks canonical position for PRNG seed."
  "Classic TXs get indexes 0..N-1, Soroban gets N..N+M-1."
  global_tx_offset = classic_tx_count
```

**Calls**: [pre_deduct_soroban_fees](#pre_deduct_soroban_fees) | [execute_stage_clusters](#execute_stage_clusters)

```
  --- Pre-charge fees ---
  if external_pre_charged provided:
    pre_charged_fees = external_pre_charged
  else:
    (pre_charged_fees, total_pre_deducted)
      = pre_deduct_soroban_fees(snapshot, phase, ...)
    if total_pre_deducted != 0:
      delta.record_fee_pool_delta(total_pre_deducted)

  --- Prefetch all Soroban TX keys ---
  all_keys = empty set
  for each stage, cluster, (tx, _) in phase:
    add frame.keys_for_fee_processing() to all_keys
    add frame.keys_for_apply() to all_keys
  snapshot.prefetch(all_keys)

  --- Execute stages sequentially ---
  pre_charge_offset = 0
  for each (stage_idx, stage) in phase.stages:
    if stage is empty: skip

    "Collect current entries from delta so clusters see"
    "changes from prior stages AND classic TX changes."
    prior_stage_entries = delta.current_entries()
    stage_tx_count = sum of cluster lengths in stage
    stage_pre_charged = pre_charged_fees[
      pre_charge_offset .. pre_charge_offset + stage_tx_count]

    cluster_results = execute_stage_clusters(
      snapshot, stage, global_tx_offset, context, soroban,
      delta, { id_pool, prior_stage_entries, stage_pre_charged })

    --- Merge cluster results ---
    for each cr in cluster_results:
      id_pool = max(id_pool, cr.id_pool)
      collect cr.results, cr.tx_results, cr.tx_result_metas
      collect cr.hot_archive_restored_keys

    global_tx_offset += stage_tx_count
    pre_charge_offset += stage_tx_count

  --- Apply fee refunds after ALL transactions ---
  "Matches stellar-core processPostTxSetApply()"
  for each (idx, result) in all_results:
    refund = result.fee_refund
    if refund > 0:
      source = fee_source_account_id(flat_txs[idx])
      delta.apply_refund_to_account(source, refund)
      total_refunds += refund
  if total_refunds > 0:
    delta.record_fee_pool_delta(-total_refunds)

  → TxSetResult { all_results, all_tx_results,
      all_tx_result_metas, id_pool, hot_archive_restored_keys }
```

### pre_deduct_all_fees_on_delta

"Matches stellar-core processFeesSeqNums() which processes fees for"
"ALL transactions across both phases before any transaction body executes."
"Order: classic phase first, then Soroban phase."

```
pre_deduct_all_fees_on_delta(classic_txs, soroban_phase,
    base_fee, network_id, ledger_seq, delta, snapshot):
  total_fee_pool = 0
```

**Calls**: [fee_source_account_id](#fee_source_account_id)

```
  --- Phase 0: Classic fees ---
  for each (tx, tx_base_fee) in classic_txs:
    tx_fee = tx_base_fee or base_fee
    num_ops = max(1, frame.operation_count())
    if frame.is_fee_bump():
      required_fee = tx_fee * (num_ops + 1)
    else:
      required_fee = tx_fee * num_ops

    inclusion_fee = frame.inclusion_fee()
    if frame.is_soroban():
      computed_fee = declared_soroban_resource_fee
        + min(inclusion_fee, required_fee)
    else:
      computed_fee = min(inclusion_fee, required_fee)

    (charged_fee, fee_changes)
      = delta.deduct_fee_from_account(fee_source, computed_fee,
          snapshot, ledger_seq)
    total_fee_pool += charged_fee
    append { charged_fee,
             should_apply = (charged_fee >= computed_fee),
             fee_changes }

  --- Phase 1: Soroban fees ---
  for each stage, cluster, (tx, tx_base_fee) in soroban_phase:
    "Same fee computation as classic but always Soroban:"
    computed_fee = declared_soroban_resource_fee
      + min(inclusion_fee, required_fee)
    (charged_fee, fee_changes)
      = delta.deduct_fee_from_account(...)
    total_fee_pool += charged_fee
    append { charged_fee, should_apply, fee_changes }

  → (classic_pre_charged, soroban_pre_charged, total_fee_pool)
```

### Helper: soroban_write_footprint

```
soroban_write_footprint(tx):
  "Extract read-write footprint keys from a Soroban transaction."
  extract SorobanTransactionData from tx envelope (V1 ext)
  GUARD not found → none
  → data.resources.footprint.read_write keys
```

### execute_single_cluster

"Execute a single cluster of transactions independently."
"Fees are NOT deducted by the executor (pre-deducted from main delta)."

```
execute_single_cluster(snapshot, cluster, cluster_offset,
    context, soroban, params):
  executor = new TransactionExecutor(context, params.id_pool, ...)
  if soroban.module_cache: set it
  if soroban.hot_archive: set it

  "Pre-load entries from prior stages so this cluster sees"
  "restorations and modifications from earlier stages."
  "Matches stellar-core collectClusterFootprintEntriesFromGlobal."
  for each entry in params.prior_stage_entries:
    executor.state.load_entry(entry)
```

**Calls**: [soroban_write_footprint](#soroban_write_footprint) | [sub_sha256](signatures.pc.md#sub_sha256) | [build_tx_result_pair](result_mapping.pc.md#build_tx_result_pair)

```
  for each (local_idx, (tx, tx_base_fee)) in cluster:
    "Flush pending RO TTL bumps for write footprint keys."
    "Must happen BEFORE snapshot_delta so flushed values"
    "are not rolled back on TX failure."
    if tx has Soroban write footprint:
      executor.state.flush_ro_ttl_bumps_for_write_footprint(keys)

    executor.state.snapshot_delta()

    tx_fee = tx_base_fee or context.base_fee
    global_idx = cluster_offset + local_idx
    tx_prng_seed = sub_sha256(soroban.base_prng_seed, global_idx)

    result = executor.execute_transaction_with_fee_mode(
      snapshot, tx, tx_fee, tx_prng_seed, deduct_fee=false)

    "Override fee_charged from pre-deduction values"
    pre = params.pre_charged_fees[local_idx]
    result.fee_charged = pre.charged_fee - result.fee_refund
    result.fee_changes = pre.fee_changes

    "If pre-deduction found insufficient balance, force failure"
    if not pre.should_apply and result.success:
      result.success = false
      result.failure = InsufficientBalance

    build tx_result, tx_result_meta
    collect results

  executor.state.flush_deferred_ro_ttl_bumps()

  cluster_delta = new LedgerDelta
  executor.apply_to_delta(snapshot, cluster_delta)

  → (TxSetResult, cluster_delta, total_fees)
```

### execute_stage_clusters

"Execute all clusters within a stage."
"Single cluster: inline execution. Multiple: parallel via thread pool."

```
execute_stage_clusters(snapshot, clusters, global_tx_offset,
    context, soroban, delta, params):

  --- Compute per-cluster offsets ---
  offsets = []
  pre_charge_offsets = []
  offset = global_tx_offset
  pc_offset = 0
  for each cluster in clusters:
    append offset to offsets
    append pc_offset to pre_charge_offsets
    offset += cluster.len()
    pc_offset += cluster.len()
```

**Calls**: [execute_single_cluster](#execute_single_cluster)

```
  --- Single-cluster fast path ---
  if clusters.len() <= 1:
    for each (cluster_idx, cluster) in clusters:
      (cr, cluster_delta, total_fees)
        = execute_single_cluster(snapshot, cluster,
            offsets[cluster_idx], context, soroban, ...)
      delta.merge(cluster_delta)
      if total_fees != 0:
        delta.record_fee_pool_delta(total_fees)
    → cluster_results

  --- Multi-cluster parallel path ---
  "Spawn one blocking task per cluster on thread pool."
  for each cluster index:
    spawn_blocking:
      execute_single_cluster(snapshot, cluster,
        cluster_offset, context, soroban, cluster_params)

  "Collect all results preserving cluster order."
  await all tasks

  "Merge results in cluster order (deterministic)."
  for each (cr, cluster_delta, total_fees) in results:
    delta.merge(cluster_delta)
    if total_fees != 0:
      delta.record_fee_pool_delta(total_fees)

  → cluster_results
```

### compute_state_size_window_entry

"Implements stellar-core maybeSnapshotSorobanStateSize logic."
"Updates LiveSorobanStateSizeWindow config setting on each sample period."

```
compute_state_size_window_entry(seq, protocol_version,
    bucket_list, soroban_state_size):

  GUARD protocol_version < MIN_SOROBAN_PROTOCOL_VERSION → none

  --- Load archival settings ---
  archival = bucket_list.get(StateArchival config key)
  GUARD archival missing → none
  sample_period = archival.live_soroban_state_size_window_sample_period
  sample_size = archival.live_soroban_state_size_window_sample_size
  GUARD sample_period == 0 or sample_size == 0 → none

  --- Load current window ---
  window = bucket_list.get(LiveSorobanStateSizeWindow config key)
  GUARD window missing or empty → none

  changed = false

  --- Adjust window size if needed ---
  if window.len() != sample_size:
    if sample_size < window.len():
      remove (window.len() - sample_size) oldest entries
    else:
      insert (sample_size - window.len()) copies of oldest entry
    changed = true

  --- Update window on sample ledgers ---
  if seq % sample_period == 0 and window not empty:
    remove oldest entry
    append soroban_state_size
    changed = true

  GUARD not changed → none

  → LedgerEntry { last_modified = seq,
      data = LiveSorobanStateSizeWindow(window) }
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 1024   | 250        |
| Functions     | 9      | 9          |
