# Caching During Ledger Close: stellar-core vs henyey

## 1. Per-Bucket Entry Cache (ACCOUNT lookups)

| | stellar-core | henyey |
|---|---|---|
| **Type** | `RandomEvictionCache<LedgerKey, BucketEntry>` per bucket index | `RandomEvictionCache` per `DiskBucket` |
| **Cached types** | ACCOUNT only | ACCOUNT only |
| **Eviction** | Least-recent-of-2-random-choices | Least-recent-of-2-random-choices |
| **Sizing** | Proportional to account fraction in each bucket | Proportional to account bytes in each bucket |
| **Default limit** | Config-driven (per-bucket proportional) | 1 GB / 2M entries, with per-bucket proportional split |
| **Activation** | Always active for disk-backed buckets | Only if bucket list has >= 1M entries |
| **Parity** | Equivalent design and policy |

## 2. LedgerTxnRoot Entry Cache (cross-transaction)

| | stellar-core | henyey |
|---|---|---|
| **Type** | `RandomEvictionCache<LedgerKey, LedgerEntry>` in `LedgerTxnRoot::Impl` | **Does not exist** |
| **Default size** | 100,000 entries (`ENTRY_CACHE_SIZE`) | — |
| **Scope** | Persists across all transactions within a single ledger close | — |
| **What it caches** | Any `LedgerEntry` loaded from bucket list during apply (classic entries only) | — |
| **Populated by** | `load()` calls + `prefetch()` bulk loads | — |

**This is the biggest gap.** In stellar-core, the `LedgerTxnRoot` entry cache sits between transaction execution and the bucket list. When transaction A loads account X, and transaction B later loads the same account X, the second load hits this cache instead of traversing the bucket list again. Henyey has no equivalent — every `SnapshotHandle::lookup()` for a non-Soroban key goes directly to the per-bucket cache or disk.

## 3. Prefetch (bulk load before apply)

| | stellar-core | henyey |
|---|---|---|
| **Source ID prefetch** | `prefetchTxSourceIds()` — loads all tx source accounts before fee processing | **Does not exist** |
| **Transaction data prefetch** | `prefetchTransactionData()` — `insertKeysForTxApply()` collects all keys needed, bulk-loads into entry cache via `loadKeys()` | **Does not exist** |
| **Best-offer prefetch** | `populateEntryCacheFromBestOffers()` — for each offer, preloads seller account + trustlines into entry cache | **Does not exist** |
| **Soroban keys** | Explicitly excluded from prefetch (loaded via `InMemorySorobanState`) | N/A — Soroban state is in-memory |

**This is the second biggest gap.** stellar-core does two prefetch passes before applying transactions:
1. **Fee processing keys** — all source accounts loaded in a single `loadKeys()` batch
2. **Apply keys** — all keys from `insertKeysForTxApply()` loaded in a single batch

The `loadKeys()` path does a single sweep through all bucket levels for the entire key set, which is far more efficient than individual point lookups. The results are inserted into the `LedgerTxnRoot` entry cache with `LoadType::PREFETCH`. During subsequent apply, ~everything is already cached.

Henyey has a `batch_lookup_fn` on `SnapshotHandle`, but it's only used for Soroban operations (RestoreFootprint, ExtendTTL) — not for classic transaction prefetch.

## 4. InMemorySorobanState

| | stellar-core | henyey |
|---|---|---|
| **Type** | `InMemorySorobanState` (unordered_set with custom entries) | `InMemorySorobanState` (HashMap-based) |
| **Contents** | ContractData, ContractCode with embedded TTLs | ContractData, ContractCode with embedded TTLs |
| **Populated** | `populateInMemorySorobanState()` from bucket list snapshot at startup | `scan_bucket_list_for_caches()` at startup |
| **Updated** | `updateInMemorySorobanState()` after each ledger apply | Updated incrementally via `process_entry_create/update/delete` |
| **Parity** | Equivalent — both avoid bucket list lookups for all Soroban types |

## 5. In-Memory Offer Store

| | stellar-core | henyey |
|---|---|---|
| **Type** | `InMemoryLedgerTxnRoot` with `mAllOffers` unordered_map | `HashMap<i64, LedgerEntry>` + `(account, asset) -> Set<offer_id>` index |
| **Contents** | All live offers by LedgerKey | All live offers by offer_id + secondary index |
| **Secondary index** | `getBestOffer()` method with asset-based lookup | `OffersByAccountAssetFn` closure |
| **Populated** | From bucket list scan at init | From bucket list scan at init |
| **Best-offer cache warm** | `populateEntryCacheFromBestOffers()` preloads seller accounts + trustlines for upcoming offers | **Does not exist** |
| **Parity** | Core functionality equivalent; henyey lacks the associated trustline/account prefetch |

## 6. Soroban Module Cache

| | stellar-core | henyey |
|---|---|---|
| **Type** | Rust `SorobanModuleCache` (via `rust_bridge`) | `PersistentModuleCache` |
| **Contents** | Compiled Wasm modules | Compiled Wasm modules |
| **Populated** | At init, parallel compilation across bucket levels | At init, parallel compilation across bucket levels |
| **Eviction** | On contract eviction | `remove_contract()` on eviction |
| **Parity** | Equivalent |

## 7. Bloom Filters

| | stellar-core | henyey |
|---|---|---|
| **Type** | `BinaryFuseFilter16` in `DiskIndex` | `BinaryFuse16` in bucket index |
| **Purpose** | Fast negative for "key not in bucket" — skip disk I/O | Same |
| **Parity** | Equivalent |

## 8. Bucket Index (Range/Page)

| | stellar-core | henyey |
|---|---|---|
| **Small buckets** | `InMemoryIndex` — full key->offset map | `InMemoryIndex` — full key->offset HashMap |
| **Large buckets** | `DiskIndex` with `RangeIndex` (page-based lower/upper bounds) | `DiskIndex` with page-based ranges |
| **Persistence** | `.index` files on disk | `.bucket.index` files on disk |
| **Parity** | Equivalent |

## 9. Bucket Snapshot Manager

| | stellar-core | henyey |
|---|---|---|
| **Type** | `BucketSnapshotManager` — current + historical snapshots | No equivalent snapshot manager |
| **Historical** | FIFO ring of `QUERY_SNAPSHOT_LEDGERS` past snapshots | Not needed (no RPC layer) |
| **Thread safety** | Snapshots are immutable, shared via `shared_ptr` for parallel threads | Bucket list behind `RwLock`, snapshot cloned for execution |
| **Parity** | Structurally different but functionally similar for close path |

## 10. Background Eviction Scan

| | stellar-core | henyey |
|---|---|---|
| **Type** | `mEvictionFuture` — async scan on background thread, cached result | Inline during `close_ledger` |
| **Iterator** | Resumes from persisted `EvictionIterator` position | Same — persisted iterator position |
| **Parity** | Henyey does eviction inline rather than async, but the iterator caching is equivalent |

## Summary of Gaps

| Gap | Impact | Notes |
|---|---|---|
| **No `LedgerTxnRoot` entry cache** | High | stellar-core: 100K entry RandomEvictionCache across all txs in a ledger. Repeated classic entry lookups within same ledger hit bucket list every time in henyey. |
| **No prefetch passes** | High | stellar-core does 2 batch `loadKeys()` passes, warming entry cache. Source accounts and tx keys not bulk-loaded before apply in henyey. |
| **No best-offer account/trustline prefetch** | Medium | stellar-core preloads seller + buying/selling trustlines into entry cache. During path payment in henyey, seller accounts loaded individually. |
| **No background eviction scan** | Low | Eviction is fast relative to total close time. Could help with tail latency. |

The two most impactful missing caches are the **LedgerTxnRoot entry cache** and the **prefetch mechanism**. Together they mean that in stellar-core, by the time a transaction actually executes, most of the entries it needs are already in a fast in-memory cache. In henyey, every classic entry lookup during execution goes through the per-bucket cache (which only covers ACCOUNTs) or all the way to disk.
