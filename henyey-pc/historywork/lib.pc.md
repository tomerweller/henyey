## Pseudocode: historywork/lib.rs

"History work items for Stellar catchup and publish workflows.
Building blocks for downloading and publishing history archive data.
Integrates with the work scheduler for dependency management and retry logic."

CONST MAX_CONCURRENT_DOWNLOADS = 16  // matches stellar-core MAX_CONCURRENT_SUBPROCESSES
CONST CHECKPOINT_FREQUENCY = 64      // checkpoints every 64 ledgers
CONST WELL_KNOWN_DIR = ".well-known"
CONST WELL_KNOWN_STELLAR_HISTORY = "stellar-history.json"

### Helper: set_progress
```
function set_progress(state, stage, message):
    lock state
    MUTATE state progress.stage = stage
    MUTATE state progress.message = message
```

### GetHistoryArchiveStateWork.run
"Fetches the HAS JSON from the archive. Root of the download DAG — no dependencies."
```
function run(ctx):
    set_progress(state, FetchHas, "fetching HAS")
    has = archive.get_checkpoint_has(checkpoint)
    GUARD has fetched ok → Failed("failed to fetch HAS: ...")

    lock state
    MUTATE state has = has
    → Success
```

**Calls**: [set_progress](#helper-set_progress) | [HistoryArchive.get_checkpoint_has](../history/lib.pc.md#get_checkpoint_has)

### DownloadBucketsWork.run
"Downloads and hash-verifies all buckets referenced by the HAS.
Each bucket is verified, saved to disk, then dropped from memory."
```
function run(ctx):
    set_progress(state, DownloadBuckets, "downloading buckets")

    has = lock state → state.has
    GUARD has exists → Failed("missing HAS")

    hashes = content_bucket_hashes(has)
    total = hashes.len()

    create bucket_dir if not exists
    GUARD dir created ok → Failed("failed to create bucket dir: ...")

    "filter out buckets already cached on disk"
    to_download = hashes where file not exists on disk

    if to_download is empty:
        "all buckets already cached"
    else:
        "download in parallel (up to MAX_CONCURRENT_DOWNLOADS)"
        for each hash in to_download (parallel, buffered):
            data = archive.get_bucket(hash)
            GUARD download ok → error message

            verify_bucket_hash(data, hash)
            GUARD hash ok → error("bucket hash mismatch: ...")

            write data to disk as "{hash}.bucket.xdr"
            GUARD write ok → error("failed to save bucket: ...")

            "data dropped here — not held in memory"

        "check all results for failures"
        for each result:
            GUARD result ok → Failed(err)

    lock state
    MUTATE state bucket_dir = bucket_dir
    → Success
```

**Calls**: [set_progress](#helper-set_progress) | [content_bucket_hashes](#helper-content_bucket_hashes) | [verify_bucket_hash](../history/lib.pc.md#verify_bucket_hash)

### DownloadLedgerHeadersWork.run
"Downloads headers for 64 ledgers, verifies the header chain."
```
function run(ctx):
    set_progress(state, DownloadHeaders, "downloading headers")

    headers = archive.get_ledger_headers(checkpoint)
    GUARD download ok → Failed("failed to download headers: ...")

    header_chain = extract header from each entry
    verify_header_chain(header_chain)
    GUARD chain ok → Failed("header chain verification failed: ...")

    lock state
    MUTATE state headers = headers
    → Success
```

**Calls**: [set_progress](#helper-set_progress) | [verify_header_chain](../history/lib.pc.md#verify_header_chain)

### DownloadTransactionsWork.run
"Downloads transaction sets and verifies each against its ledger header hash."
```
function run(ctx):
    set_progress(state, DownloadTransactions, "downloading transactions")

    entries = archive.get_transactions(checkpoint)
    GUARD download ok → Failed("failed to download transactions: ...")

    headers = lock state → state.headers

    for each entry in entries:
        header = find header where ledger_seq matches entry
        GUARD header found → skip (continue)

        tx_set = if entry.ext is V0:
                     ClassicTxSet(entry.tx_set)
                 else (V1):
                     GeneralizedTxSet(entry.ext.generalized_set)

        verify_tx_set(header, tx_set)
        GUARD verification ok → Failed("tx set hash mismatch: ...")

    lock state
    MUTATE state transactions = entries
    → Success
```

**Calls**: [set_progress](#helper-set_progress) | [verify_tx_set](../history/lib.pc.md#verify_tx_set)

### DownloadTxResultsWork.run
"Downloads transaction results and verifies each against its header's result hash."
```
function run(ctx):
    headers = lock state → state.headers

    set_progress(state, DownloadResults, "downloading transaction results")

    results = archive.get_results(checkpoint)
    GUARD download ok → Failed("failed to download tx results: ...")

    for each entry in results:
        header = find header where ledger_seq matches entry
        GUARD header found → skip
        xdr = serialize entry.tx_result_set to XDR
        GUARD serialization ok → skip
        verify_tx_result_set(header, xdr)
        GUARD verification ok → Failed("tx result set hash mismatch: ...")

    lock state
    MUTATE state tx_results = results
    → Success
```

**Calls**: [set_progress](#helper-set_progress) | [verify_tx_result_set](../history/lib.pc.md#verify_tx_result_set)

### DownloadScpHistoryWork.run
"Downloads SCP consensus messages for the checkpoint."
```
function run(ctx):
    set_progress(state, DownloadScp, "downloading SCP history")

    entries = archive.get_scp_history(checkpoint)
    GUARD download ok → Failed("failed to download SCP history: ...")

    lock state
    MUTATE state scp_history = entries
    → Success
```

**Calls**: [set_progress](#helper-set_progress)

### LocalArchiveWriter.put_bytes
```
function put_bytes(path, data):
    full_path = base_dir / path
    create parent directories if needed
    write data to full_path
```

### Helper: gzip_bytes
```
function gzip_bytes(data) → compressed:
    → gzip compress data with default level
```

### Helper: serialize_entries
"History archive files contain sequences of XDR entries without length prefixes."
```
function serialize_entries(entries) → bytes:
    data = empty buffer
    for each entry in entries:
        xdr = entry.to_xdr()
        data.append(xdr)
    → data
```

### Helper: publish_xdr_entries
"Common publish pipeline: serialize → gzip → write."
```
function publish_xdr_entries(writer, entries, category, checkpoint, extension):
    data = serialize_entries(entries)
    GUARD ok → error("failed to serialize {category}: ...")
    gz = gzip_bytes(data)
    GUARD ok → error("failed to gzip {category}: ...")
    path = checkpoint_path(category, checkpoint, extension)
    writer.put_bytes(path, gz)
    GUARD ok → error("failed to publish {category}: ...")
```

**Calls**: [serialize_entries](#helper-serialize_entries) | [gzip_bytes](#helper-gzip_bytes) | [checkpoint_path](../history/lib.pc.md#checkpoint_path)

### Helper: content_bucket_hashes
"Returns non-empty, non-zero bucket hashes from a HAS."
```
function content_bucket_hashes(has) → list of hashes:
    empty_hash = sha256("")
    → has.unique_bucket_hashes()
        filtered where hash != zero and hash != empty_hash
```

### well_known_stellar_history_path
```
→ ".well-known/stellar-history.json"
```

### PublishHistoryArchiveStateWork.run
"Publishes the HAS JSON to both the checkpoint path and well-known path (RFC 5785)."
```
function run(ctx):
    set_progress(state, PublishHas, "publishing HAS")

    has = lock state → state.has
    GUARD has exists → Failed("HAS not available")

    json = has.to_json()
    GUARD ok → Failed("failed to serialize HAS: ...")

    "publish to checkpoint-specific path"
    cp_path = checkpoint_path("history", checkpoint, "json")
    writer.put_bytes(cp_path, json)
    GUARD ok → Failed("failed to publish HAS to checkpoint path: ...")

    "publish to well-known path (RFC 5785)"
    wk_path = well_known_stellar_history_path()
    writer.put_bytes(wk_path, json)
    GUARD ok → Failed("failed to publish HAS to well-known path: ...")

    → Success
```

**Calls**: [set_progress](#helper-set_progress) | [well_known_stellar_history_path](#well_known_stellar_history_path) | [checkpoint_path](../history/lib.pc.md#checkpoint_path)

### PublishBucketsWork.run
"Reads each bucket from disk, gzip-compresses, and publishes."
```
function run(ctx):
    set_progress(state, PublishBuckets, "publishing buckets")

    (bucket_dir, has) = lock state → (state.bucket_dir, state.has)
    GUARD bucket_dir exists → Failed("bucket directory not available")
    GUARD has exists → Failed("HAS not available for publish")

    hashes = content_bucket_hashes(has)

    for each hash in hashes:
        file_path = bucket_dir / "{hash}.bucket.xdr"
        data = read file
        GUARD read ok → Failed("failed to read bucket from disk: ...")
        gz = gzip_bytes(data)
        GUARD ok → Failed("failed to gzip bucket: ...")
        path = bucket_path(hash)
        writer.put_bytes(path, gz)
        GUARD ok → Failed("failed to publish bucket: ...")

    → Success
```

**Calls**: [set_progress](#helper-set_progress) | [content_bucket_hashes](#helper-content_bucket_hashes) | [gzip_bytes](#helper-gzip_bytes) | [bucket_path](../history/lib.pc.md#bucket_path)

### PublishLedgerHeadersWork.run
```
function run(ctx):
    set_progress(state, PublishHeaders, "publishing headers")
    headers = lock state → state.headers
    → publish_xdr_entries(writer, headers, "ledger", checkpoint, "xdr.gz")
```

**Calls**: [set_progress](#helper-set_progress) | [publish_xdr_entries](#helper-publish_xdr_entries)

### PublishTransactionsWork.run
```
function run(ctx):
    set_progress(state, PublishTransactions, "publishing transactions")
    transactions = lock state → state.transactions
    → publish_xdr_entries(writer, transactions, "transactions", checkpoint, "xdr.gz")
```

**Calls**: [set_progress](#helper-set_progress) | [publish_xdr_entries](#helper-publish_xdr_entries)

### PublishResultsWork.run
```
function run(ctx):
    set_progress(state, PublishResults, "publishing results")
    results = lock state → state.tx_results
    → publish_xdr_entries(writer, results, "results", checkpoint, "xdr.gz")
```

**Calls**: [set_progress](#helper-set_progress) | [publish_xdr_entries](#helper-publish_xdr_entries)

### PublishScpHistoryWork.run
```
function run(ctx):
    set_progress(state, PublishScp, "publishing SCP history")
    entries = lock state → state.scp_history

    GUARD entries not empty → Failed("SCP history not available")

    → publish_xdr_entries(writer, entries, "scp", checkpoint, "xdr.gz")
```

**Calls**: [set_progress](#helper-set_progress) | [publish_xdr_entries](#helper-publish_xdr_entries)

### CheckSingleLedgerHeaderWork.run
"Downloads checkpoint headers and verifies a single ledger header matches expected."
```
function run(ctx):
    ledger_seq = expected.header.ledger_seq

    "genesis ledger has no header in the archive"
    GUARD ledger_seq != 0 → Success

    headers = archive.get_ledger_headers(ledger_seq)
    GUARD download ok → Failed("failed to download headers for ledger: ...")

    found = find header where ledger_seq matches
    GUARD found → Failed("ledger header not found in checkpoint")

    if found.hash == expected.hash and found.header == expected.header:
        → Success
    else:
        → Failed("ledger header mismatch at seq: expected hash ..., got ...")
```

### HistoryWorkBuilder.register
"Registers all download work items with proper dependency ordering."
```
function register(scheduler) → HistoryWorkIds:
    "--- download DAG ---"
    has_id       = scheduler.add_work(GetHistoryArchiveStateWork, deps=[], retries=3)
    buckets_id   = scheduler.add_work(DownloadBucketsWork,        deps=[has_id], retries=3)
    headers_id   = scheduler.add_work(DownloadLedgerHeadersWork,  deps=[has_id], retries=3)
    tx_id        = scheduler.add_work(DownloadTransactionsWork,   deps=[headers_id], retries=3)
    tx_results_id = scheduler.add_work(DownloadTxResultsWork,     deps=[headers_id, tx_id], retries=3)
    scp_id       = scheduler.add_work(DownloadScpHistoryWork,     deps=[headers_id], retries=3)

    → HistoryWorkIds{has, buckets, headers, tx, tx_results, scp}
```

**Calls**: [WorkScheduler.add_work](lib.pc.md#add_work)

### HistoryWorkBuilder.register_publish
"Registers publish work items, each depending on its download counterpart."
```
function register_publish(scheduler, writer, deps) → PublishWorkIds:
    has_id     = scheduler.add_work(PublishHASWork,         deps=[deps.has], retries=2)
    buckets_id = scheduler.add_work(PublishBucketsWork,     deps=[deps.buckets], retries=2)
    headers_id = scheduler.add_work(PublishHeadersWork,     deps=[deps.headers], retries=2)
    tx_id      = scheduler.add_work(PublishTransactionsWork, deps=[deps.transactions], retries=2)
    results_id = scheduler.add_work(PublishResultsWork,     deps=[deps.tx_results], retries=2)
    scp_id     = scheduler.add_work(PublishScpHistoryWork,  deps=[deps.scp_history], retries=2)

    → PublishWorkIds{has, buckets, headers, transactions, results, scp}
```

**Calls**: [WorkScheduler.add_work](lib.pc.md#add_work)

### get_progress
```
function get_progress(state) → HistoryWorkProgress:
    lock state
    → state.progress
```

### CheckpointRange.new
```
function new(first, last):
    ASSERT: first <= last
    → CheckpointRange{first, last}
```

### CheckpointRange.count
```
function count():
    first_idx = first / CHECKPOINT_FREQUENCY
    last_idx = last / CHECKPOINT_FREQUENCY
    → last_idx - first_idx + 1
```

### CheckpointRange.iter
```
→ sequence from first to last, step CHECKPOINT_FREQUENCY
```

### CheckpointRange.ledger_range
```
function ledger_range() → (first_ledger, last_ledger):
    if first <= CHECKPOINT_FREQUENCY:
        first_ledger = 1
    else:
        first_ledger = first - CHECKPOINT_FREQUENCY + 1
    → (first_ledger, last)
```

### Helper: download_checkpoint_file
```
function download_checkpoint_file(archive, checkpoint, file_type):
    if file_type is Ledger:
        → archive.get_ledger_headers(checkpoint) as Headers
    else if file_type is Transactions:
        → archive.get_transactions(checkpoint) as Transactions
    else if file_type is Results:
        → archive.get_results(checkpoint) as Results
    else if file_type is Scp:
        → archive.get_scp_history(checkpoint) as Scp
```

### BatchDownloadWork.run
"Downloads files of a specific type for a range of checkpoints in parallel."
```
function run(ctx):
    checkpoints = range.iter() as list
    total = checkpoints.len()

    "update progress"
    lock state
    MUTATE state progress = {file_type, total, completed=0, current=first}

    "download all checkpoints in parallel (buffered to MAX_CONCURRENT_DOWNLOADS)"
    results = for each checkpoint in checkpoints (parallel, buffered):
        data = download_checkpoint_file(archive, checkpoint, file_type)
        lock state
        MUTATE state progress.completed += 1
        MUTATE state progress.current = checkpoint
        → (checkpoint, data)

    "process results and store in state"
    lock state
    for each (checkpoint, data) in results:
        GUARD result ok → Failed(err)
        if data is Headers:    state.headers[checkpoint] = data
        if data is Transactions: state.transactions[checkpoint] = data
        if data is Results:    state.tx_results[checkpoint] = data
        if data is Scp:        state.scp_history[checkpoint] = data

    → Success
```

**Calls**: [download_checkpoint_file](#helper-download_checkpoint_file)

### BatchDownloadWorkBuilder.register
"Registers batch download work with dependency ordering matching single-checkpoint pattern."
```
function register(scheduler) → BatchDownloadWorkIds:
    headers_id = scheduler.add_work(
        BatchDownloadWork(archive, range, Ledger, state), deps=[], retries=3)
    tx_id = scheduler.add_work(
        BatchDownloadWork(archive, range, Transactions, state), deps=[headers_id], retries=3)
    results_id = scheduler.add_work(
        BatchDownloadWork(archive, range, Results, state), deps=[headers_id, tx_id], retries=3)
    scp_id = scheduler.add_work(
        BatchDownloadWork(archive, range, Scp, state), deps=[headers_id], retries=3)

    → BatchDownloadWorkIds{headers, transactions, results, scp}
```

**Calls**: [WorkScheduler.add_work](lib.pc.md#add_work)

### build_checkpoint_data
```
function build_checkpoint_data(state) → CheckpointData:
    lock state
    has = state.has
    GUARD has exists → error("missing History Archive State")

    bucket_dir = state.bucket_dir
    GUARD bucket_dir exists → error("bucket directory not set")

    → CheckpointData{has, bucket_dir,
        headers, transactions, tx_results, scp_history}
```

### HistoryFileType.type_string
```
function type_string():
    if Ledger:       → "ledger"
    if Transactions: → "transactions"
    if Results:      → "results"
    if Scp:          → "scp"
```

### BatchDownloadProgress.message
```
function message() → string:
    if file_type set:
        → "downloading {file_type} files: {completed}/{total} checkpoints"
    else:
        → "batch download not started"
```

## Summary
| Metric | Source | Pseudocode |
|--------|--------|------------|
| Lines (logic) | ~950 (excl. docs, structs, tests) | ~285 |
| Functions | 35 | 35 |
