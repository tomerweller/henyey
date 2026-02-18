## Pseudocode: crates/herder/src/parallel_tx_set_builder.rs

"Parallel transaction set building for Soroban phases. Partitions Soroban
transactions into stages and clusters for parallel execution."

"Algorithm:
1. Conflict detection: RW-RW and RO-RW footprint overlaps
2. Stage building: Greedily assign txs to stages, merging conflicts into clusters
3. Bin packing: First-fit-decreasing to pack clusters into bins
4. Multi-stage optimization: Pick fewest stages achieving >= 99.9% of max fee"

### Constants

```
CONST MAX_INCLUSION_FEE_TOLERANCE = 0.999
```

---

### Data: BitSet

"Simple growable bitset for conflict tracking."

```
BitSet:
  words     // list<u64>
```

### BitSet::with_capacity

```
function with_capacity(bits) → BitSet:
  word_count = ceil(bits / 64)
  → BitSet { words: [0] * word_count }
```

### BitSet::set

```
function set(idx):
  word = idx / 64
  if word >= words.length: grow to word + 1
  words[word] |= (1 << (idx % 64))
```

### BitSet::get

```
function get(idx) → bool:
  word = idx / 64
  if word >= words.length: → false
  → (words[word] & (1 << (idx % 64))) != 0
```

### BitSet::intersects

```
function intersects(other) → bool:
  for i in 0..min(words.length, other.words.length):
    if words[i] & other.words[i] != 0:
      → true
  → false
```

### BitSet::union_with

```
function union_with(other):
  if other.words.length > words.length: grow
  for each (i, w) in other.words:
    words[i] |= w
```

### BitSet::difference_with

```
function difference_with(other):
  for i in 0..min(words.length, other.words.length):
    words[i] &= ~other.words[i]
```

### BitSet::iter_ones

```
function iter_ones() → iterator<int>:
  for each (word_idx, word) in words:
    for bit in 0..64:
      if word & (1 << bit) != 0:
        yield word_idx * 64 + bit
```

---

### Data: BuilderTx

```
BuilderTx:
  id              // index in original tx list
  instructions    // u32 — from SorobanResources
  conflicts       // BitSet — which other txs conflict
```

### Data: Cluster

```
Cluster:
  instructions    // u64 — total instructions
  conflicts       // BitSet — union of all member conflicts
  tx_ids          // BitSet — member transaction IDs
```

### Cluster::from_tx

```
function from_tx(tx) → Cluster:
  tx_ids = BitSet with tx.id set
  → Cluster { instructions: tx.instructions,
              conflicts: tx.conflicts, tx_ids }
```

### Cluster::merge

```
function merge(other):
  self.instructions += other.instructions
  self.conflicts.union_with(other.conflicts)
  self.tx_ids.union_with(other.tx_ids)
```

---

### Data: ParallelPartitionConfig

```
ParallelPartitionConfig:
  clusters_per_stage          // u32
  instructions_per_cluster    // u64
```

### ParallelPartitionConfig::new

```
function new(stage_count, ledger_max_instructions,
             ledger_max_dependent_tx_clusters):
  instructions_per_cluster =
    if stage_count > 0:
      ledger_max_instructions / stage_count
    else:
      ledger_max_instructions
  → { clusters_per_stage: ledger_max_dependent_tx_clusters,
      instructions_per_cluster }
```

### instructions_per_stage

```
function instructions_per_stage() → u64:
  → instructions_per_cluster * clusters_per_stage
```

---

### Data: Stage

```
Stage:
  clusters                      // list<Cluster>
  bin_packing                   // list<BitSet> — tx IDs per bin
  bin_instructions              // list<u64> — instructions per bin
  total_instructions            // u64
  config                        // ParallelPartitionConfig
  tried_compacting_bin_packing  // bool
```

### Stage::new

```
function new(config) → Stage:
  n = config.clusters_per_stage
  → Stage { clusters: [], bin_packing: [empty] * n,
            bin_instructions: [0] * n, total_instructions: 0,
            config, tried_compacting_bin_packing: false }
```

### Stage::try_add

"Try to add a transaction to this stage. Returns true if successful."

```
function try_add(tx) → bool:
  "Fast fail: check total instructions"
  if total_instructions + tx.instructions > config.instructions_per_stage():
    → false

  "Find clusters that conflict with this TX"
  conflicting_indices = [i for (i, c) in clusters
                         where c.conflicts.get(tx.id)]

  "Create new cluster set: merge conflicting + new TX"
  new_clusters = create_new_clusters(tx, conflicting_indices)
  if new_clusters is null:
    → false

  "Try in-place bin packing (greedy first-fit)"
  merged_cluster = last element of new_clusters
  if try_in_place_bin_packing(merged_cluster, conflicting_indices):
    clusters = new_clusters
    total_instructions += tx.instructions
    → true

  "Optimization: skip if no conflicts and already tried compacting"
  if conflicting_indices is empty and tried_compacting_bin_packing:
    → false

  "Full bin packing recomputation (first-fit-decreasing)"
  new_bin_instructions = [0] * clusters_per_stage
  new_packing = bin_pack_clusters(new_clusters,
      config.clusters_per_stage,
      config.instructions_per_cluster,
      new_bin_instructions)

  if new_packing is not null:
    clusters = new_clusters
    bin_packing = new_packing
    bin_instructions = new_bin_instructions
    total_instructions += tx.instructions
    → true
  else:
    if conflicting_indices is empty:
      tried_compacting_bin_packing = true
    → false
```

### Stage::create_new_clusters

"Merge all conflicting clusters with the new TX."

```
function create_new_clusters(tx, conflicting_indices) → list<Cluster>?:
  merged = Cluster::from_tx(tx)

  "Merge all conflicting clusters into it"
  for each idx in conflicting_indices:
    merged.merge(clusters[idx])

  "Check merged cluster instruction limit"
  if merged.instructions > config.instructions_per_cluster:
    → null

  "Build: non-conflicting clusters + merged cluster"
  new_clusters = [c for (i, c) in clusters
                  where i not in conflicting_indices]
  new_clusters.append(merged)
  → new_clusters
```

### Stage::try_in_place_bin_packing

"Try greedy in-place bin packing. Returns true if new cluster fits."

```
function try_in_place_bin_packing(new_cluster, conflicting_indices) → bool:
  "Remove conflicting clusters from their bins"
  removed = []
  for each idx in conflicting_indices:
    cluster = clusters[idx]
    for each (bin_id, bin) in bin_packing:
      if bin.intersects(cluster.tx_ids):
        removed.append((bin_id, cluster.instructions, cluster.tx_ids))
        bin_instructions[bin_id] -= cluster.instructions
        bin_packing[bin_id].difference_with(cluster.tx_ids)
        break

  "Try to fit new cluster into an existing bin"
  for bin_id in 0..clusters_per_stage:
    if bin_instructions[bin_id] + new_cluster.instructions
        <= config.instructions_per_cluster:
      bin_instructions[bin_id] += new_cluster.instructions
      bin_packing[bin_id].union_with(new_cluster.tx_ids)
      → true

  "Revert removals"
  for each (bin_id, insns, tx_ids) in removed:
    bin_instructions[bin_id] += insns
    bin_packing[bin_id].union_with(tx_ids)
  → false
```

---

### bin_pack_clusters

"First-fit-decreasing bin packing for clusters."

```
function bin_pack_clusters(clusters, max_bins,
    max_instructions_per_bin, bin_instructions)
    → list<BitSet>?:

  bins = [empty BitSet] * max_bins

  "Sort clusters by instruction count descending (FFD)"
  sorted_indices = sort clusters descending by instructions

  for each idx in sorted_indices:
    cluster = clusters[idx]
    packed = false
    for bin_id in 0..max_bins:
      if bin_instructions[bin_id] + cluster.instructions
          <= max_instructions_per_bin:
        bin_instructions[bin_id] += cluster.instructions
        bins[bin_id].union_with(cluster.tx_ids)
        packed = true
        break
    if not packed:
      → null

  → bins
```

---

### detect_conflicts

"Detect footprint conflicts between Soroban transactions.
Two transactions conflict if both write same key (RW-RW) or
one reads and other writes same key (RO-RW). RO-RO is NOT a conflict."

```
function detect_conflicts(txs, network_id) → list<BitSet>:
  n = len(txs)
  conflicts = [BitSet(capacity=n)] * n

  "Build key → tx maps"
  ro_key_txs = map<bytes, list<int>>
  rw_key_txs = map<bytes, list<int>>

  for each (tx_id, tx) in txs:
    frame = TransactionFrame(tx, network_id)
    soroban_data = frame.soroban_data()
    if soroban_data exists:
      for each key in soroban_data.footprint.read_only:
        ro_key_txs[serialize(key)].append(tx_id)
      for each key in soroban_data.footprint.read_write:
        rw_key_txs[serialize(key)].append(tx_id)

  "Mark RW-RW conflicts"
  for each rw_txs in rw_key_txs.values():
    for each pair (a, b) in rw_txs:
      conflicts[a].set(b)
      conflicts[b].set(a)

  "Mark RO-RW conflicts"
  for each (key, rw_txs) in rw_key_txs:
    if key in ro_key_txs:
      for each ro_tx in ro_key_txs[key]:
        for each rw_tx in rw_txs:
          if ro_tx != rw_tx:
            conflicts[ro_tx].set(rw_tx)
            conflicts[rw_tx].set(ro_tx)

  → conflicts
```

### Helper: tx_inclusion_fee

```
function tx_inclusion_fee(tx) → i64:
  "Use declared fee as proxy for inclusion fee"
  → tx.fee
```

---

### build_with_stage_count

"Build parallel Soroban phase for a fixed stage count."

```
function build_with_stage_count(txs, network_id,
    ledger_max_instructions, ledger_max_dependent_tx_clusters,
    stage_count) → (stages, total_inclusion_fee):

  conflicts = detect_conflicts(txs, network_id)

  "Build BuilderTx representations"
  builder_txs = for each (id, tx) in txs:
    frame = TransactionFrame(tx, network_id)
    instructions = frame.soroban_data().resources.instructions or 0
    BuilderTx { id, instructions, conflicts: conflicts[id] }

  "Sort by fee rate descending for greedy assignment"
  sorted_ids = sort tx indices by tx_inclusion_fee descending

  "Build stages greedily"
  stages = [Stage(config) for _ in 0..stage_count]
  total_inclusion_fee = 0

  for each tx_id in sorted_ids:
    tx_ref = builder_txs[tx_id]
    added = false
    for each stage in stages:
      if stage.try_add(tx_ref):
        added = true
        break
    if added:
      total_inclusion_fee += tx_inclusion_fee(txs[tx_id])
    "If not added, TX is dropped (doesn't fit)"

  "Extract results: stage → cluster → tx envelopes"
  result_stages = for each stage:
    for each cluster in stage:
      [txs[id] for id in cluster.tx_ids.iter_ones()]
    filter out empty clusters
  filter out empty stages

  → (result_stages, total_inclusion_fee)
```

---

### build_parallel_soroban_phase

"Build optimal parallel Soroban phase. Tries multiple stage counts,
picks fewest stages achieving >= 99.9% of max fee."

```
function build_parallel_soroban_phase(soroban_txs, network_id,
    ledger_max_instructions, ledger_max_dependent_tx_clusters,
    min_stage_count, max_stage_count)
    → stages (list of list of list of TransactionEnvelope):

  GUARD soroban_txs is empty   → empty

  "Fallback: if clusters_per_stage is 0, single cluster"
  if ledger_max_dependent_tx_clusters == 0:
    → [[all soroban_txs]]

  "Try each stage count"
  results = []
  for sc in min_stage_count..=max_stage_count:
    result = build_with_stage_count(soroban_txs, network_id,
        ledger_max_instructions, ledger_max_dependent_tx_clusters, sc)
    results.append(result)

  "Find max inclusion fee across all results"
  max_fee = max of all fees in results
  fee_threshold = max_fee * MAX_INCLUSION_FEE_TOLERANCE

  "Pick fewest stages meeting threshold (results ordered ascending)"
  for each (stages, fee) in results:
    if fee >= fee_threshold:
      → stages

  → empty
```

### stages_to_xdr_phase

"Convert stages into TransactionPhase::V1 XDR structure."

```
function stages_to_xdr_phase(stages, base_fee) → TransactionPhase:
  execution_stages = for each stage in stages:
    clusters = for each cluster in stage:
      DependentTxCluster(cluster)
    ParallelTxExecutionStage(clusters)

  → TransactionPhase::V1(ParallelTxsComponent {
      base_fee, execution_stages })
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~640   | ~245       |
| Functions     | 21     | 21         |
