## Pseudocode: crates/overlay/src/message_handlers.rs

### Data Structures

```
TxSetData:
  variant Legacy(TransactionSet)
  variant Generalized(GeneralizedTransactionSet)

MessageDispatcher:
  tx_set_fetcher: ItemFetcher
  quorum_set_fetcher: ItemFetcher
  tx_set_cache: Map<Hash, TxSetData>
  quorum_set_cache: Map<Hash, ScpQuorumSet>
  on_tx_set: callback or null
  on_quorum_set: callback or null
  on_envelopes_ready: callback or null

MessageDispatcherStats:
  tx_set_fetcher_stats: ItemFetcherStats
  quorum_set_fetcher_stats: ItemFetcherStats
  cached_tx_sets: int
  cached_quorum_sets: int
```

### TxSetData::hash

```
function hash():
  bytes = xdr_encode(self)
  → sha256(bytes)
```

### new

```
function new():
  tx_set_fetcher = ItemFetcher(TxSet)
  quorum_set_fetcher = ItemFetcher(QuorumSet)
  tx_set_cache = empty map
  quorum_set_cache = empty map
  → MessageDispatcher with null callbacks
```

### handle_message

```
function handle_message(from_peer, message):
  if message is GetTxSet(hash):
    → handle_get_tx_set(from_peer, hash)
  if message is TxSet(tx_set):
    handle_tx_set_data(from_peer, Legacy(tx_set))
    → null
  if message is GeneralizedTxSet(tx_set):
    handle_tx_set_data(from_peer, Generalized(tx_set))
    → null
  if message is GetScpQuorumset(hash):
    → handle_get_quorum_set(from_peer, hash)
  if message is ScpQuorumset(qs):
    handle_quorum_set(from_peer, qs)
    → null
  if message is DontHave(dont_have):
    handle_dont_have(from_peer, dont_have)
    → null
  → null
```

### handle_get_tx_set

```
function handle_get_tx_set(from_peer, hash):
  "Check if we have this TxSet cached"
  if hash in tx_set_cache:
    tx_set = tx_set_cache[hash]
    if tx_set is Legacy:
      → TxSet message
    if tx_set is Generalized:
      → GeneralizedTxSet message

  "We don't have it, send DONT_HAVE"
  → DontHave { type: TxSet, hash }
```

### handle_tx_set_data

```
function handle_tx_set_data(from_peer, data):
  hash = data.hash()

  "Cache it"
  tx_set_cache[hash] = data

  "Notify fetcher"
  envelopes = tx_set_fetcher.recv(hash)
```

**Calls** [tx_set_fetcher.recv](item_fetcher.pc.md#recv)

```
  "Invoke callbacks"
  if on_tx_set is set:
    on_tx_set(hash, data)

  if envelopes is not empty:
    if on_envelopes_ready is set:
      on_envelopes_ready(envelopes)
```

### handle_get_quorum_set

```
function handle_get_quorum_set(from_peer, hash):
  "Check if we have this QuorumSet cached"
  if hash in quorum_set_cache:
    → ScpQuorumset message with cached value

  "We don't have it, send DONT_HAVE"
  → DontHave { type: ScpQuorumset, hash }
```

### handle_quorum_set

```
function handle_quorum_set(from_peer, quorum_set):
  hash = sha256(xdr_encode(quorum_set))

  "Cache it"
  quorum_set_cache[hash] = quorum_set

  "Notify fetcher"
  envelopes = quorum_set_fetcher.recv(hash)
```

**Calls** [quorum_set_fetcher.recv](item_fetcher.pc.md#recv)

```
  "Invoke callbacks"
  if on_quorum_set is set:
    on_quorum_set(hash, quorum_set)

  if envelopes is not empty:
    if on_envelopes_ready is set:
      on_envelopes_ready(envelopes)
```

### handle_dont_have

```
function handle_dont_have(from_peer, dont_have):
  hash = dont_have.req_hash

  if dont_have.type is TxSet or GeneralizedTxSet:
    tx_set_fetcher.doesnt_have(hash, from_peer)
  else if dont_have.type is ScpQuorumset:
    quorum_set_fetcher.doesnt_have(hash, from_peer)
```

**Calls** [tx_set_fetcher.doesnt_have](item_fetcher.pc.md#doesnt_have), [quorum_set_fetcher.doesnt_have](item_fetcher.pc.md#doesnt_have)

### fetch_tx_set

```
function fetch_tx_set(hash, envelope):
  tx_set_fetcher.fetch(hash, envelope)
```

**Calls** [tx_set_fetcher.fetch](item_fetcher.pc.md#fetch)

### fetch_quorum_set

```
function fetch_quorum_set(hash, envelope):
  quorum_set_fetcher.fetch(hash, envelope)
```

**Calls** [quorum_set_fetcher.fetch](item_fetcher.pc.md#fetch)

### stop_fetch_tx_set

```
function stop_fetch_tx_set(hash, envelope):
  tx_set_fetcher.stop_fetch(hash, envelope)
```

### stop_fetch_quorum_set

```
function stop_fetch_quorum_set(hash, envelope):
  quorum_set_fetcher.stop_fetch(hash, envelope)
```

### stop_fetching_below

```
function stop_fetching_below(slot_index, slot_to_keep):
  tx_set_fetcher.stop_fetching_below(slot_index, slot_to_keep)
  quorum_set_fetcher.stop_fetching_below(slot_index, slot_to_keep)
```

### get_pending_tx_set_requests

```
function get_pending_tx_set_requests(peers):
  → tx_set_fetcher.get_pending_requests(peers)
```

### get_pending_quorum_set_requests

```
function get_pending_quorum_set_requests(peers):
  → quorum_set_fetcher.get_pending_requests(peers)
```

### has_tx_set / has_quorum_set

```
function has_tx_set(hash):
  → hash in tx_set_cache

function has_quorum_set(hash):
  → hash in quorum_set_cache
```

### get_tx_set / get_quorum_set

```
function get_tx_set(hash):
  → tx_set_cache[hash] or null

function get_quorum_set(hash):
  → quorum_set_cache[hash] or null
```

### cache_tx_set / cache_quorum_set

```
function cache_tx_set(hash, data):
  tx_set_cache[hash] = data

function cache_quorum_set(hash, quorum_set):
  quorum_set_cache[hash] = quorum_set
```

### stats

```
function stats():
  → MessageDispatcherStats {
      tx_set_fetcher_stats,
      quorum_set_fetcher_stats,
      cached_tx_sets: tx_set_cache.length,
      cached_quorum_sets: quorum_set_cache.length
    }
```

## Summary

| Metric        | Source | Pseudocode |
|---------------|--------|------------|
| Lines (logic) | 404    | 140        |
| Functions     | 20     | 20         |
