## Pseudocode: crates/history/src/cdp.rs

"CDP Data Lake client for fetching LedgerCloseMeta."
"Implements SEP-0054 for reading ledger metadata from Stellar's"
"Composable Data Platform (CDP) in cloud object storage (S3, GCS)."

"Data Organization:"
"  {base_url}/{date}/{inverted_start}--{start}-{end}/{inverted_seq}--{seq}.xdr.zst"
"The inverted prefix ensures lexicographic ordering matches chronological ordering."

### Constants and Data Structures

```
CONST CDP_PARTITION_SIZE = 64000  // ledgers per partition

CdpDataLake:
  base_url: string
  client: HTTP client
  date_partition: string  // "YYYY-MM-DD"

CachedCdpDataLake:
  inner: CdpDataLake
  cache_dir: path
  prefetch_count: int     // default 16

CacheStats:
  entries: int
  size_bytes: u64
  cache_dir: path

TransactionProcessingInfo:
  envelope: TransactionEnvelope
  result: TransactionResultPair
  meta: TransactionMeta
  fee_meta: LedgerEntryChanges
  post_fee_meta: LedgerEntryChanges
  base_fee: u32 or null
```

### CdpDataLake::partition_for_ledger

```
function partition_for_ledger(ledger_seq):
  partition_start = (ledger_seq / CDP_PARTITION_SIZE)
                    * CDP_PARTITION_SIZE
  partition_end = partition_start + CDP_PARTITION_SIZE - 1
  inverted = MAX_U32 - partition_start
  → format "{inverted:08X}--{start}-{end}"
```

### CdpDataLake::batch_filename

```
function batch_filename(ledger_seq):
  inverted = MAX_U32 - ledger_seq
  → format "{inverted:08X}--{ledger_seq}.xdr.zst"
```

### CdpDataLake::url_for_ledger

```
function url_for_ledger(ledger_seq):
  partition = partition_for_ledger(ledger_seq)
  filename = batch_filename(ledger_seq)
  if date_partition is empty:
    → "{base_url}/{partition}/{filename}"
  else:
    → "{base_url}/{date_partition}/{partition}/{filename}"
```

### CdpDataLake::get_ledger_close_meta

```
async function get_ledger_close_meta(ledger_seq):
  url = url_for_ledger(ledger_seq)
  response = HTTP GET url
  GUARD response not success → HttpStatus error

  compressed_data = response.bytes()
  decompressed = decompress_zstd(compressed_data)
  → parse_ledger_close_meta_batch(decompressed, ledger_seq)
```

### CdpDataLake::get_ledger_close_metas

```
async function get_ledger_close_metas(start_seq, end_seq):
  metas = []
  for seq in start_seq..=end_seq:
    meta = get_ledger_close_meta(seq)
    append meta to metas
  → metas
```

### Helper: decompress_zstd

```
function decompress_zstd(data):
  decoder = new ZstdDecoder(data)
  → decoder.read_to_end()
```

### CdpDataLake::parse_ledger_close_meta_batch

"SEP-0054 batch format:"
"  struct LedgerCloseMetaBatch {"
"    uint32 startSequence;"
"    uint32 endSequence;"
"    LedgerCloseMeta ledgerCloseMetas<>;"
"  }"

```
function parse_ledger_close_meta_batch(data, requested_ledger):
  GUARD data.length < 8 → "batch too short"

  start_seq = big_endian_u32(data[0..4])
  end_seq = big_endian_u32(data[4..8])

  GUARD requested_ledger < start_seq
        or requested_ledger > end_seq
    → "ledger not in batch range"

  GUARD data.length < 12 → "missing array length"
  count = big_endian_u32(data[8..12])

  "Single-ledger fast path"
  if count == 1 and start_seq == end_seq:
    → parse LedgerCloseMeta from data[12..]

  "Multi-ledger batch: iterate to find requested"
  offset = 12
  for i in 0..count:
    current_ledger = start_seq + i
    meta = parse LedgerCloseMeta from data[offset..]
    if current_ledger == requested_ledger:
      → meta
    offset += xdr_size(meta)

  → "ledger not found in batch"
```

### CdpDataLake::decompress_and_parse

```
function decompress_and_parse(compressed, ledger_seq):
  decompressed = decompress_zstd(compressed)
  → parse_ledger_close_meta_batch(decompressed, ledger_seq)
```

### CachedCdpDataLake::new

```
function CachedCdpDataLake_new(base_url, date_partition,
    cache_dir, network):
  cache_path = cache_dir / "cdp" / network
  if date_partition is not empty:
    cache_path = cache_path / date_partition
  create cache_path directories

  → CachedCdpDataLake {
      inner: CdpDataLake(base_url, date_partition),
      cache_dir: cache_path,
      prefetch_count: 16
    }
```

### CachedCdpDataLake::get_ledger_close_meta

```
async function get_ledger_close_meta(ledger_seq):
  cache_path = cache_dir / "{ledger_seq}.xdr.zst"

  if cache_path exists:
    compressed = read cache_path
    → inner.decompress_and_parse(compressed, ledger_seq)

  → fetch_and_cache(ledger_seq)
```

### CachedCdpDataLake::fetch_and_cache

```
async function fetch_and_cache(ledger_seq):
  url = inner.url_for_ledger(ledger_seq)
  response = HTTP GET url
  GUARD response not success → HttpStatus error

  compressed_data = response.bytes()
  write compressed_data to cache_path(ledger_seq)
  → inner.decompress_and_parse(compressed_data, ledger_seq)
```

### CachedCdpDataLake::prefetch

"Downloads and caches ledgers not already cached, in parallel."

```
async function prefetch(start, end):
  to_fetch = filter (start..=end) where not is_cached(seq)
  GUARD to_fetch is empty → 0

  results = parallel_stream(to_fetch)
    .map(seq → fetch_and_cache(seq))
    .buffer_unordered(prefetch_count)
    .collect()

  → count of successful results
```

### CachedCdpDataLake::get_ledger_close_metas_prefetch

"Fetch range: prefetch uncached in parallel, then read all from cache."

```
async function get_ledger_close_metas_prefetch(start, end):
  uncached = filter (start..=end) where not is_cached(seq)

  if uncached is not empty:
    downloaded = atomic counter(0)
    parallel_stream(uncached)
      .map(seq →
        fetch_and_cache(seq)
        downloaded += 1)
      .buffer_unordered(prefetch_count)
      .collect()

  "Read all from cache (should all be populated)"
  metas = []
  for seq in start..=end:
    meta = get_ledger_close_meta(seq)
    append meta to metas
  → metas
```

### CachedCdpDataLake cache management

```
function delete_cached(ledger_seq):
  path = cache_path(ledger_seq)
  if path exists:
    delete path
    → true
  → false

function delete_cached_range(start, end):
  → count of delete_cached(seq) returning true
    for seq in start..=end

function cached_count(start, end):
  → count of is_cached(seq) for seq in start..=end

function cache_stats():
  (entries, size_bytes) = scan cache_dir for files
  → CacheStats { entries, size_bytes, cache_dir }
```

### extract_transaction_metas

"Returns TransactionMeta for each tx in execution order."
"Metadata is in transaction apply order."

```
function extract_transaction_metas(meta):
  if meta is V0: → v0.tx_processing.map(tp → tp.tx_apply_processing)
  if meta is V1: → v1.tx_processing.map(tp → tp.tx_apply_processing)
  if meta is V2: → v2.tx_processing.map(tp → tp.tx_apply_processing)
```

### extract_ledger_header

```
function extract_ledger_header(meta):
  if meta is V0: → v0.ledger_header.header
  if meta is V1: → v1.ledger_header.header
  if meta is V2: → v2.ledger_header.header
```

### extract_transaction_envelopes

```
function extract_transaction_envelopes(meta):
  if meta is V0: → v0.tx_set.txs
  if meta is V1: → extract_txs_from_generalized_set(v1.tx_set)
  if meta is V2: → extract_txs_from_generalized_set(v2.tx_set)
```

### Helper: extract_txs_from_generalized_set

```
function extract_txs_from_generalized_set(tx_set):
  txs = []
  for each phase in tx_set.v1.phases:
    if phase is V0(components):
      for each component in components:
        append component.txs to txs
    if phase is V1(parallel):
      for each stage in parallel.execution_stages:
        for each cluster in stage:
          append cluster.txs to txs
  → txs
```

### extract_transaction_set

```
function extract_transaction_set(meta):
  if meta is V0: → Classic(v0.tx_set)
  if meta is V1: → Generalized(v1.tx_set)
  if meta is V2: → Generalized(v2.tx_set)
```

### extract_transaction_results

```
function extract_transaction_results(meta):
  → tx_processing.map(tp → tp.result)
    NOTE: dispatched for V0/V1/V2
```

### Helper: compute_tx_hash

"Compute network-aware transaction hash."

```
function compute_tx_hash(envelope, network_id):
  hasher = new SHA256
  hasher.update(network_id)

  envelope_type =
    if TxV0: EnvelopeType.TxV0
    if Tx:   EnvelopeType.Tx
    if TxFeeBump: EnvelopeType.TxFeeBump
  hasher.update(envelope_type as big-endian i32)

  tx_xdr = envelope.tx.to_xdr()
  hasher.update(tx_xdr)
  → hasher.finalize()
```

### Helper: build_tx_hash_to_base_fee_map

"The GeneralizedTransactionSet can contain per-phase/per-component"
"base fees that differ from header.base_fee during surge pricing."

```
function build_tx_hash_to_base_fee_map(tx_set, network_id):
  map = {}
  for each phase in tx_set.v1.phases:
    if phase is V0(components):
      for each component in components:
        base_fee = component.base_fee or null
        for each env in component.txs:
          hash = compute_tx_hash(env, network_id)
          map[hash] = base_fee

    if phase is V1(parallel):
      base_fee = parallel.base_fee or null
      for each stage in parallel.execution_stages:
        for each cluster in stage:
          for each env in cluster.txs:
            hash = compute_tx_hash(env, network_id)
            map[hash] = base_fee
  → map
```

### extract_transaction_processing

"Align tx envelopes with results and metadata in apply order."
"Complex because tx sets may be ordered differently than apply order."

```
function extract_transaction_processing(meta, network_id):
  if meta is V0:
    "V0: tx_set.txs and tx_processing align by index"
    result = []
    for each (i, tp) in v0.tx_processing:
      envelope = v0.tx_set.txs[i]
      append TransactionProcessingInfo {
        envelope, tp.result, tp.tx_apply_processing,
        tp.fee_processing,
        post_fee_meta: empty,
        base_fee: null
      }
    → result

  if meta is V1:
    txs = extract_txs_from_generalized_set(v1.tx_set)
    tx_map = build_tx_hash_map_with_network(txs, network_id)
    base_fee_map = build_tx_hash_to_base_fee_map(v1.tx_set, network_id)
    result = []
    for each tp in v1.tx_processing:
      tx_hash = tp.result.transaction_hash
      envelope = tx_map[tx_hash]
      GUARD envelope not found → skip (warn)
      append TransactionProcessingInfo {
        envelope, tp.result, tp.tx_apply_processing,
        tp.fee_processing,
        post_fee_meta: empty,
        base_fee: base_fee_map[tx_hash]
      }
    → result

  if meta is V2:
    NOTE: same as V1 except post_fee_meta = tp.post_tx_apply_fee_processing
    txs = extract_txs_from_generalized_set(v2.tx_set)
    tx_map = build_tx_hash_map_with_network(txs, network_id)
    base_fee_map = build_tx_hash_to_base_fee_map(v2.tx_set, network_id)
    result = []
    for each tp in v2.tx_processing:
      tx_hash = tp.result.transaction_hash
      envelope = tx_map[tx_hash]
      GUARD envelope not found → skip (warn)
      append TransactionProcessingInfo {
        envelope, tp.result, tp.tx_apply_processing,
        tp.fee_processing,
        post_fee_meta: tp.post_tx_apply_fee_processing,
        base_fee: base_fee_map[tx_hash]
      }
    → result
```

### extract_ledger_close_data

"Create LedgerCloseData from LedgerCloseMeta for replay."

```
function extract_ledger_close_data(meta, prev_ledger_hash):
  header = extract_ledger_header(meta)
  tx_set = extract_transaction_set(meta)

  upgrades = []
  for each upgrade_bytes in header.scp_value.upgrades:
    upgrade = parse LedgerUpgrade from upgrade_bytes
    if parse succeeds:
      append upgrade to upgrades

  → LedgerCloseData.new(
      header.ledger_seq, tx_set,
      header.scp_value.close_time,
      prev_ledger_hash
    ).with_upgrades(upgrades)
     .with_stellar_value_ext(header.scp_value.ext)
```

### extract_evicted_keys

"V2-only: entries evicted from live bucket list."

```
function extract_evicted_keys(meta):
  if meta is V0 or V1: → empty
  if meta is V2: → v2.evicted_keys
```

### extract_restored_keys

"Extract restored ledger keys from transaction metadata."
"Only CONTRACT_DATA and CONTRACT_CODE keys are recorded in hot archive."
"TTL keys are NOT included, matching stellar-core behavior."

```
function extract_restored_keys(tx_metas):
  restored_keys = []

  for each meta in tx_metas:
    for each change in all_changes(meta):
      if change is Restored(entry):
        key = ledger_entry_to_key(entry)
        if key is ContractData or ContractCode:
          append key to restored_keys
        NOTE: skip TTL keys and other types

  NOTE: all_changes processes differently per version:
    V0: operations[].changes
    V1: tx_changes + operations[].changes
    V2/V3/V4: tx_changes_before + operations[].changes
               + tx_changes_after

  → restored_keys
```

### extract_upgrade_metas

```
function extract_upgrade_metas(meta):
  if meta is V0: → v0.upgrades_processing
  if meta is V1: → v1.upgrades_processing
  if meta is V2: → v2.upgrades_processing
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | ~1070  | ~290       |
| Functions     | 24     | 24         |
