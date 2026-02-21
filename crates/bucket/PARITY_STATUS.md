# stellar-core Parity Status

**Crate**: `henyey-bucket`
**Upstream**: `stellar-core/src/bucket/`
**Overall Parity**: 93%
**Last Updated**: 2026-02-17

## Summary

| Area | Status | Notes |
|------|--------|-------|
| BucketListBase (spill mechanics, level math) | Full | All static functions implemented |
| LiveBucketList (addBatch, eviction) | Full | Includes eviction iterator management |
| HotArchiveBucketList (addBatch) | Full | Archive and restore support |
| BucketBase (merge, hash, index) | Full | Unified Bucket type covers both Live/HotArchive |
| LiveBucket (fresh, merge, in-memory) | Full | Includes mergeInMemory and freshInMemoryOnly |
| HotArchiveBucket (fresh, merge) | Full | Full merge semantics |
| BucketManager (lifecycle, GC, state) | Partial | Missing some medida metrics, merge future integration |
| FutureBucket (async merging) | Full | Tokio-based equivalent |
| BucketSnapshot (thread-safe reads) | Full | Full snapshot hierarchy |
| BucketSnapshotManager (snapshot lifecycle) | Full | Historical snapshots supported |
| SearchableBucketListSnapshot (queries) | Full | Pool queries, inflation winners, type scanning |
| BucketInputIterator / OutputIterator | Full | Streaming with metadata handling |
| LiveBucketIndex / DiskIndex / InMemoryIndex | Full | Page-based + bloom filter + cache |
| BucketApplicator (catchup) | Full | Chunked application with counters |
| BucketMergeMap (dedup) | Partial | Implemented but not integrated into merge workflow |
| LedgerCmp / BucketEntryIdCmp | Full | Full entry ordering |

## File Mapping

| stellar-core File | Rust Module | Notes |
|--------------------|-------------|-------|
| `BucketBase.h` / `BucketBase.cpp` | `bucket.rs` | Unified `Bucket` type (no CRTP template) |
| `LiveBucket.h` / `LiveBucket.cpp` | `bucket.rs`, `merge.rs` | In-memory entries, merge logic |
| `HotArchiveBucket.h` / `HotArchiveBucket.cpp` | `hot_archive.rs` | Separate type for hot archive |
| `BucketListBase.h` / `BucketListBase.cpp` | `bucket_list.rs`, `eviction.rs` | Level math, spill logic |
| `LiveBucketList.h` / `LiveBucketList.cpp` | `bucket_list.rs` | addBatch, eviction iterator |
| `HotArchiveBucketList.h` / `HotArchiveBucketList.cpp` | `hot_archive.rs` | Hot archive addBatch |
| `BucketManager.h` / `BucketManager.cpp` | `manager.rs`, `bucket_list.rs` | Bucket lifecycle, state loading |
| `FutureBucket.h` / `FutureBucket.cpp` | `future_bucket.rs`, `bucket_list.rs` | Async merge + PendingMerge |
| `BucketInputIterator.h` / `BucketInputIterator.cpp` | `iterator.rs` | Streaming input iteration |
| `BucketOutputIterator.h` / `BucketOutputIterator.cpp` | `iterator.rs` | Streaming output with dedup |
| `BucketSnapshot.h` / `BucketSnapshot.cpp` | `snapshot.rs` | Thread-safe bucket snapshots |
| `BucketSnapshotManager.h` / `BucketSnapshotManager.cpp` | `snapshot.rs` | Snapshot lifecycle |
| `BucketListSnapshotBase.h` / `BucketListSnapshotBase.cpp` | `snapshot.rs` | Searchable snapshot base |
| `SearchableBucketList.h` / `SearchableBucketList.cpp` | `snapshot.rs` | Query interface |
| `LiveBucketIndex.h` / `LiveBucketIndex.cpp` | `index.rs` | Hybrid index facade |
| `DiskIndex.h` / `DiskIndex.cpp` | `index.rs` | Page-based range index |
| `InMemoryIndex.h` / `InMemoryIndex.cpp` | `index.rs` | Full in-memory index |
| `HotArchiveBucketIndex.h` / `HotArchiveBucketIndex.cpp` | `hot_archive.rs` | Simplified (disk-only) |
| `BucketIndexUtils.h` / `BucketIndexUtils.cpp` | `index.rs`, `bloom_filter.rs` | Index utilities and filter |
| `BucketApplicator.h` / `BucketApplicator.cpp` | `applicator.rs` | Catchup entry application |
| `BucketMergeMap.h` / `BucketMergeMap.cpp` | `merge_map.rs` | Merge dedup tracking |
| `BucketMergeAdapter.h` | *(intentional omission)* | Rust generics replace C++ template adapters |
| `MergeKey.h` / `MergeKey.cpp` | `future_bucket.rs` | Merge key type |
| `LedgerCmp.h` | `entry.rs` | Entry comparison/ordering |
| `BucketUtils.h` / `BucketUtils.cpp` | `entry.rs`, `eviction.rs`, `metrics.rs` | Utility types and counters |

## Component Mapping

### `bucket.rs`

Corresponds to: `BucketBase.h`, `LiveBucket.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `BucketBase()` (empty) | `Bucket::empty()` | Full |
| `BucketBase(filename, hash, index)` | `Bucket::from_xdr_file_disk_backed()` | Full |
| `getHash()` | `Bucket::hash()` | Full |
| `getFilename()` | `Bucket::backing_file_path()` | Full |
| `getSize()` | `Bucket::len()` | Full |
| `isEmpty()` | `Bucket::is_empty()` | Full |
| `freeIndex()` | *(drop semantics)* | Full |
| `isIndexed()` | `Bucket::is_disk_backed()` | Full |
| `setIndex()` | `Bucket::from_xdr_file_disk_backed_prebuilt()` | Full |
| `merge()` | `merge_buckets()` / `merge_buckets_with_options()` | Full |
| `mergeInternal()` | Internal merge logic in `merge.rs` | Full |
| `randomBucketName()` | `canonical_bucket_filename()` | Full |
| `LiveBucket()` (empty) | `Bucket::empty()` | Full |
| `LiveBucket(filename, hash, index)` | Various `Bucket::from_*` constructors | Full |
| `containsBucketIdentity()` | `Bucket::get()` | Full |
| `getIndexCacheSize()` | *(via LiveBucketIndex)* | Full |
| `checkProtocolLegality()` | Inline protocol checks in merge | Full |
| `convertToBucketEntry()` | Inline in `BucketList::add_batch()` | Full |
| `mergeCasesWithEqualKeys()` | `merge_entries()` in `merge.rs` | Full |
| `fresh()` | `Bucket::from_entries()` / `from_sorted_entries()` | Full |
| `freshInMemoryOnly()` | `Bucket::fresh_in_memory_only()` | Full |
| `isTombstoneEntry()` | `BucketEntry::is_dead()` | Full |
| `bucketEntryToLoadResult()` | `Bucket::get_entry()` | Full |
| `maybePut()` | Shadow handling in `merge.rs` | Full |
| `mergeInMemory()` | `merge_in_memory()` | Full |
| `countOldEntryType()` / `countNewEntryType()` | `MergeCounters` recording | Full |
| `updateMergeCountersForProtocolVersion()` | Inline protocol version checks | Full |
| `getBucketVersion()` | `Bucket::protocol_version()` | Full |
| `hasInMemoryEntries()` | `Bucket::has_in_memory_entries()` | Full |
| `setInMemoryEntries()` | `Bucket::set_in_memory_entries()` | Full |
| `getInMemoryEntries()` | `Bucket::get_in_memory_entries()` | Full |
| `maybeInitializeCache()` | *(via cache.rs)* | Full |
| `getBucketEntryCounters()` | *(via index.rs BucketEntryCounters)* | Full |
| `getRangeForType()` | *(via index.rs TypeRange)* | Full |

### `bucket_list.rs`

Corresponds to: `BucketListBase.h`, `LiveBucketList.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `BucketListBase()` | `BucketList::new()` | Full |
| `kNumLevels` | `BUCKET_LIST_LEVELS` (11) | Full |
| `shouldMergeWithEmptyCurr()` | Inline in spill logic | Full |
| `levelSize()` | `level_size()` | Full |
| `levelHalf()` | `level_half()` | Full |
| `sizeOfCurr()` | `size_of_curr()` | Full |
| `sizeOfSnap()` | `size_of_snap()` | Full |
| `oldestLedgerInCurr()` | `oldest_ledger_in_curr()` | Full |
| `oldestLedgerInSnap()` | `oldest_ledger_in_snap()` | Full |
| `levelShouldSpill()` | `level_should_spill()` | Full |
| `keepTombstoneEntries()` | Inline level check | Full |
| `bucketUpdatePeriod()` | `bucket_update_period()` | Full |
| `getLevel()` | `BucketList::level()` | Full |
| `getHash()` | `BucketList::hash()` | Full |
| `restartMerges()` | `BucketList::restart_merges_from_has()` | Full |
| `resolveAnyReadyFutures()` | `BucketList::resolve_ready_futures()` | Full |
| `futuresAllResolved()` | `BucketList::futures_all_resolved()` | Full |
| `getMaxMergeLevel()` | Inline calculation | Full |
| `getSize()` | `BucketList::size()` | Full |
| `addBatchInternal()` | `BucketList::add_batch()` | Full |
| `BucketLevel(i)` | `BucketLevel::new()` | Full |
| `BucketLevel::getHash()` | `BucketLevel::hash()` | Full |
| `BucketLevel::getNext()` | `BucketLevel::next()` | Full |
| `BucketLevel::getCurr()` | `BucketLevel::curr()` | Full |
| `BucketLevel::getSnap()` | `BucketLevel::snap()` | Full |
| `BucketLevel::setNext()` | `BucketLevel::set_next()` | Full |
| `BucketLevel::setCurr()` | `BucketLevel::set_curr()` | Full |
| `BucketLevel::setSnap()` | `BucketLevel::set_snap()` | Full |
| `BucketLevel::commit()` | `BucketLevel::commit()` | Full |
| `BucketLevel::prepare()` | `BucketLevel::prepare()` | Full |
| `BucketLevel::prepareFirstLevel()` | `BucketLevel::prepare_first_level()` | Full |
| `BucketLevel::snap()` | `BucketLevel::snap_curr()` | Full |
| `LiveBucketList::addBatch()` | `BucketList::add_batch()` | Full |
| `LiveBucketList::updateStartingEvictionIterator()` | `update_starting_eviction_iterator()` | Full |
| `LiveBucketList::updateEvictionIterAndRecordStats()` | Inline in eviction scan | Full |
| `LiveBucketList::checkIfEvictionScanIsStuck()` | Inline in eviction scan | Full |
| `LiveBucketList::sumBucketEntryCounters()` | *(via BucketEntryCounters)* | Full |
| `LiveBucketList::maybeInitializeCaches()` | *(via cache initialization)* | Full |

### `merge.rs`

Corresponds to: `BucketBase.h` (merge), `LiveBucket.h` (mergeCasesWithEqualKeys)

| stellar-core | Rust | Status |
|--------------|------|--------|
| `BucketBase::merge()` | `merge_buckets()` | Full |
| `BucketBase::mergeInternal()` | Internal merge loop | Full |
| `LiveBucket::mergeCasesWithEqualKeys()` | `merge_entries()` | Full |
| `LiveBucket::maybePut()` | Shadow + tombstone logic | Full |
| `LiveBucket::mergeInMemory()` | `merge_in_memory()` | Full |

### `hot_archive.rs`

Corresponds to: `HotArchiveBucket.h`, `HotArchiveBucketList.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `HotArchiveBucket()` | `HotArchiveBucket::empty()` | Full |
| `HotArchiveBucket(filename, hash, index)` | `HotArchiveBucket::from_xdr_*()` | Full |
| `getBucketVersion()` | `HotArchiveBucket::protocol_version()` | Full |
| `fresh()` | `HotArchiveBucket::fresh()` | Full |
| `isTombstoneEntry()` | `is_hot_archive_tombstone()` | Full |
| `maybePut()` | Inline in merge | Full |
| `mergeCasesWithEqualKeys()` | `merge_hot_archive_buckets()` | Full |
| `bucketEntryToLoadResult()` | `HotArchiveBucket::get()` | Full |
| `convertToBucketEntry()` | Inline in `add_batch()` | Full |
| `HotArchiveBucketList::addBatch()` | `HotArchiveBucketList::add_batch()` | Full |

### `manager.rs`

Corresponds to: `BucketManager.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `BucketManager::create()` | `BucketManager::new()` | Full |
| `initialize()` | Constructor logic | Full |
| `dropAll()` | `BucketManager::clear_cache()` + file cleanup | Full |
| `bucketIndexFilename()` | `index_path_for_bucket()` | Full |
| `getTmpDir()` | `BucketManager::bucket_dir()` | Full |
| `getBucketDir()` | `BucketManager::bucket_dir()` | Full |
| `getLiveBucketList()` | External (in app crate) | Full |
| `getHotArchiveBucketList()` | External (in app crate) | Full |
| `getBucketSnapshotManager()` | External (in app crate) | Full |
| `renameBucketDirFile()` | *(std::fs::rename)* | Full |
| `getMergeTimer()` | `MergeCounters` | Partial |
| `getBloomMissMeter()` / `getBloomLookupMeter()` | Not integrated | None |
| `getCacheHitMeter()` / `getCacheMissMeter()` | `CacheStats` | Partial |
| `readMergeCounters()` / `incrMergeCounters()` | `MergeCounters` (atomic) | Full |
| `adoptFileAsBucket()` | `BucketManager::load_bucket()` + cache | Full |
| `noteEmptyMergeOutput()` | Inline empty bucket handling | Full |
| `getBucketIfExists()` | `BucketManager::bucket_exists()` | Full |
| `getBucketByHash()` | `BucketManager::load_bucket()` | Full |
| `getMergeFuture()` | Not integrated (MergeMap exists but unused) | None |
| `putMergeFuture()` | Not integrated | None |
| `forgetUnreferencedBuckets()` | `BucketManager::retain_buckets()` | Full |
| `addLiveBatch()` | `BucketList::add_batch()` | Full |
| `addHotArchiveBatch()` | `HotArchiveBucketList::add_batch()` | Full |
| `snapshotLedger()` | `BucketList::snapshot_ledger()` | Full |
| `maybeSetIndex()` | Index set during loading | Full |
| `startBackgroundEvictionScan()` | `BucketList::scan_for_eviction_incremental()` | Full |
| `resolveBackgroundEvictionScan()` | `ResolvedEviction` | Full |
| `forgetUnreferencedBuckets()` | `BucketManager::retain_buckets()` | Full |
| `checkForMissingBucketsFiles()` | `BucketManager::verify_buckets_exist()` | Full |
| `assumeState()` | `BucketList::assume_state()` | Full |
| `shutdown()` / `isShutdown()` | *(drop semantics)* | Full |
| `loadCompleteLedgerState()` | `BucketManager::load_complete_ledger_state()` | Full |
| `loadCompleteHotArchiveState()` | `BucketManager::load_complete_hot_archive_state()` | Full |
| `mergeBuckets()` | `BucketManager::merge_all_buckets()` | Full |
| `visitLedgerEntries()` | `BucketManager::visit_ledger_entries()` / `visit_ledger_entries_of_type()` | Full |
| `scheduleVerifyReferencedBucketsWork()` | `BucketManager::verify_referenced_bucket_hashes()` | Full |
| `getConfig()` | Configuration via constructor params | Full |
| `reportBucketEntryCountMetrics()` | `BucketEntryCounters` | Partial |
| `calculateSkipValues()` | `BucketList::calculate_skip_values()` | Full |

### `future_bucket.rs`

Corresponds to: `FutureBucket.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `FutureBucket()` | `FutureBucket::clear()` | Full |
| `FutureBucket(app, curr, snap, shadows, ...)` | `FutureBucket::start_merge()` | Full |
| `clear()` | `FutureBucket::clear()` | Full |
| `isLive()` | `FutureBucket::is_live()` | Full |
| `isMerging()` | `FutureBucket::is_merging()` | Full |
| `isClear()` | `FutureBucket::is_clear()` | Full |
| `hasHashes()` | `FutureBucket::has_hashes()` | Full |
| `hasOutputHash()` | `FutureBucket::has_output_hash()` | Full |
| `getOutputHash()` | `FutureBucket::output_hash()` | Full |
| `mergeComplete()` | `MergeHandle::is_complete()` | Full |
| `resolve()` | `FutureBucket::resolve()` / `MergeHandle::resolve()` | Full |
| `makeLive()` | `FutureBucket::make_live()` | Full |
| `getHashes()` | `FutureBucket::get_hashes()` | Full |
| `load()` / `save()` (Cereal) | `FutureBucketSnapshot` serde | Full |

### `iterator.rs`

Corresponds to: `BucketInputIterator.h`, `BucketOutputIterator.h`, `BucketMergeAdapter.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `BucketInputIterator(bucket)` | `BucketInputIterator::open()` | Full |
| `operator bool()` | `BucketInputIterator::has_next()` | Full |
| `seenMetadata()` | `BucketInputIterator::seen_metadata()` | Full |
| `getMetadata()` | `BucketInputIterator::metadata()` | Full |
| `operator*()` | `BucketInputIterator::peek()` | Full |
| `operator++()` | `BucketInputIterator::next_entry()` | Full |
| `pos()` / `size()` / `seek()` | `bytes_read()` / partial | Partial |
| `BucketOutputIterator(...)` | `BucketOutputIterator::new()` | Full |
| `put()` | `BucketOutputIterator::put()` | Full |
| `getBucket()` | `BucketOutputIterator::finish()` | Full |
| `MergeInput` (virtual base) | `MergeInput` trait | Full |
| `FileMergeInput` | `FileMergeInput` | Full |
| `MemoryMergeInput` | `MemoryMergeInput` | Full |

### `snapshot.rs`

Corresponds to: `BucketSnapshot.h`, `BucketSnapshotManager.h`, `BucketListSnapshotBase.h`, `SearchableBucketList.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `BucketSnapshotBase(bucket)` | `BucketSnapshot::new()` | Full |
| `isEmpty()` | `BucketSnapshot::is_empty()` | Full |
| `getRawBucket()` | `BucketSnapshot::bucket()` | Full |
| `getBucketEntry()` | `BucketSnapshot::get()` | Full |
| `loadKeys()` | `BucketSnapshot::load_keys()` | Full |
| `getEntryAtOffset()` | Inline in disk lookup | Full |
| `LiveBucketSnapshot::getPoolIDsByAsset()` | `SearchableBucketListSnapshot::load_pool_share_trustlines_*()` | Full |
| `LiveBucketSnapshot::scanForEviction()` | Eviction scan integration | Full |
| `LiveBucketSnapshot::scanForEntriesOfType()` | `scan_for_entries_of_type()` | Full |
| `BucketListSnapshot(bl, header)` | `BucketListSnapshot::new()` | Full |
| `getLevels()` | `BucketListSnapshot::levels()` | Full |
| `getLedgerSeq()` | `BucketListSnapshot::ledger_seq()` | Full |
| `getLedgerHeader()` | `BucketListSnapshot::ledger_header()` | Full |
| `SearchableBucketListSnapshotBase::loopAllBuckets()` | Internal iteration | Full |
| `SearchableBucketListSnapshotBase::load()` | `SearchableBucketListSnapshot::load()` | Full |
| `SearchableBucketListSnapshotBase::loadKeysFromLedger()` | `load_keys_from_ledger()` | Full |
| `SearchableLiveBucketListSnapshot::loadPoolShareTrustLinesByAccountAndAsset()` | `load_pool_share_trustlines_by_account_and_asset()` | Full |
| `SearchableLiveBucketListSnapshot::loadInflationWinners()` | `load_inflation_winners()` | Full |
| `SearchableLiveBucketListSnapshot::loadKeys()` | `load_keys()` | Full |
| `SearchableLiveBucketListSnapshot::scanForEviction()` | Eviction scan integration | Full |
| `SearchableLiveBucketListSnapshot::scanForEntriesOfType()` | `scan_for_entries_of_type()` | Full |
| `SearchableHotArchiveBucketListSnapshot::loadKeys()` | `load_keys()` | Full |
| `BucketSnapshotManager::updateCurrentSnapshot()` | `update_current_snapshot()` | Full |
| `BucketSnapshotManager::copySearchableLiveBucketListSnapshot()` | `copy_searchable_live_snapshot()` | Full |
| `BucketSnapshotManager::copySearchableHotArchiveBucketListSnapshot()` | `copy_searchable_hot_archive_snapshot()` | Full |
| `BucketSnapshotManager::maybeCopySearchableBucketListSnapshot()` | `maybe_update_live_snapshot()` | Full |
| `BucketSnapshotManager::maybeCopyLiveAndHotArchiveSnapshots()` | `copy_live_and_hot_archive_snapshots()` | Full |

### `index.rs`

Corresponds to: `LiveBucketIndex.h`, `DiskIndex.h`, `InMemoryIndex.h`, `BucketIndexUtils.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `LiveBucketIndex(bm, filename, hash, ctx, hasher)` | `LiveBucketIndex::new()` | Full |
| `LiveBucketIndex::lookup()` | `LiveBucketIndex::lookup()` | Full |
| `LiveBucketIndex::scan()` | `LiveBucketIndex::scan()` | Full |
| `LiveBucketIndex::getPoolIDsByAsset()` | `LiveBucketIndex::pool_ids_by_asset()` | Full |
| `LiveBucketIndex::maybeAddToCache()` | *(via cache.rs)* | Full |
| `LiveBucketIndex::getRangeForType()` | `LiveBucketIndex::range_for_type()` | Full |
| `LiveBucketIndex::getBucketEntryCounters()` | `LiveBucketIndex::counters()` | Full |
| `LiveBucketIndex::getPageSize()` | `LiveBucketIndex::page_size()` | Full |
| `LiveBucketIndex::maybeInitializeCache()` | `LiveBucketIndex::maybe_initialize_cache()` | Full |
| `DiskIndex(bm, filename, pageSize, hash, ctx, hasher)` | `DiskIndex::new()` | Full |
| `DiskIndex::scan()` | `DiskIndex::scan()` | Full |
| `DiskIndex::getOffsetBounds()` | `DiskIndex::offset_bounds()` | Full |
| `DiskIndex::getRangeForType()` | `DiskIndex::range_for_type()` | Full |
| `DiskIndex::getPageSize()` | `DiskIndex::page_size()` | Full |
| `DiskIndex::getBucketEntryCounters()` | `DiskIndex::counters()` | Full |
| `DiskIndex::saveToDisk()` | `save_disk_index()` | Full |
| `DiskIndex::markBloomMiss()` | Bloom filter integration | Full |
| `InMemoryIndex(bm, filename, hasher)` | `InMemoryIndex::new()` | Full |
| `InMemoryBucketState::insert()` | `InMemoryIndex::insert()` | Full |
| `InMemoryBucketState::scan()` | `InMemoryIndex::scan()` | Full |
| `createIndex()` | Auto-selected in `LiveBucketIndex::new()` | Full |
| `loadIndex()` | `load_disk_index()` | Full |
| `getPageSizeFromConfig()` | `DEFAULT_PAGE_SIZE` constant | Full |
| `IndexReturnT` | Return types in scan/lookup | Full |

### `applicator.rs`

Corresponds to: `BucketApplicator.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `BucketApplicator(app, maxProtocol, ...)` | `BucketApplicator::new()` | Full |
| `operator bool()` | `BucketApplicator::has_more()` | Full |
| `advance()` | `BucketApplicator::advance()` | Full |
| `pos()` / `size()` | `BucketApplicator::progress()` | Full |
| `Counters(now)` | `ApplicatorCounters::new()` | Full |
| `Counters::mark()` | `ApplicatorCounters::record_upsert()` / `record_delete()` | Full |
| `Counters::logInfo()` / `logDebug()` | Tracing-based logging | Full |

### `merge_map.rs`

Corresponds to: `BucketMergeMap.h`

| stellar-core | Rust | Status |
|--------------|------|--------|
| `recordMerge()` | `BucketMergeMap::record_merge()` | Full |
| `forgetAllMergesProducing()` | `BucketMergeMap::forget_all_merges_producing()` | Full |
| `findMergeFor()` | `BucketMergeMap::get_output()` | Full |
| `getOutputsUsingInput()` | `BucketMergeMap::get_outputs_for_input()` | Full |

### `entry.rs`

Corresponds to: `LedgerCmp.h`, `BucketUtils.h` (entry utilities)

| stellar-core | Rust | Status |
|--------------|------|--------|
| `LedgerEntryIdCmp::operator()` | `compare_keys()` | Full |
| `BucketEntryIdCmp::compareLive()` | `compare_entries()` | Full |
| `BucketEntryIdCmp::compareHotArchive()` | Hot archive comparison in `hot_archive.rs` | Full |
| `isBucketMetaEntry()` | `BucketEntry::is_metadata()` | Full |
| `bucketEntryToLedgerEntryAndDurabilityType()` | `BucketEntryCounters::record_entry()` | Full |
| `updateTypeBoundaries()` | Index type boundary tracking | Full |
| `buildTypeRangesMap()` | `TypeRange` construction | Full |

### `metrics.rs`

Corresponds to: `BucketUtils.h` (MergeCounters, EvictionCounters)

| stellar-core | Rust | Status |
|--------------|------|--------|
| `MergeCounters` (all fields) | `MergeCounters` | Full |
| `MergeCounters::operator+=` | Atomic operations | Full |
| `EvictionResultEntry` | `EvictionCandidate` | Full |
| `EvictionResultCandidates` | `EvictionResult` | Full |
| `EvictionResultCandidates::isValid()` | `EvictionResult` validity check | Full |
| `EvictedStateVectors` | `ResolvedEviction` | Full |
| `EvictionCounters` | `EvictionCounters` | Full |
| `EvictionStatistics` | `EvictionCounters` (simplified) | Partial |
| `BucketEntryCounters` | `BucketEntryCounters` | Full |
| `LedgerEntryTypeAndDurability` | `BucketEntryCounters` (tracking by type+durability) | Full |

### `eviction.rs`

Corresponds to: `BucketListBase.h` (eviction statics), `BucketUtils.h` (eviction types)

| stellar-core | Rust | Status |
|--------------|------|--------|
| `EvictionIterator` | `EvictionIterator` | Full |
| `StateArchivalSettings` | `StateArchivalSettings` | Full |
| `updateStartingEvictionIterator()` | `update_starting_eviction_iterator()` | Full |
| `updateEvictionIterAndRecordStats()` | Inline in scan logic | Full |
| `checkIfEvictionScanIsStuck()` | Inline in scan logic | Full |
| `level_size()` / `level_half()` | `level_size()` / `level_half()` | Full |
| `level_should_spill()` | `level_should_spill()` | Full |
| `bucket_update_period()` | `bucket_update_period()` | Full |

### `bloom_filter.rs`

Corresponds to: `BucketIndexUtils.h` (BinaryFuseFilter usage)

| stellar-core | Rust | Status |
|--------------|------|--------|
| `BinaryFuseFilter16` | `BucketBloomFilter` (wraps `xorf::BinaryFuse16`) | Full |
| SipHash-2-4 key hashing | `BucketBloomFilter::hash_key()` | Full |

### `cache.rs`

Corresponds to: `RandomEvictionCache.h` (in `util/`)

| stellar-core | Rust | Status |
|--------------|------|--------|
| `RandomEvictionCache` | `RandomEvictionCache` | Full |
| `get()` / `put()` / `erase()` | `get()` / `insert()` / `remove()` | Full |
| Memory-limited eviction | Configurable max bytes/entries | Full |
| Account-only caching | `is_cached_type()` check | Full |

### `index_persistence.rs`

Corresponds to: `DiskIndex.h` (saveToDisk/loadIndex), `BucketIndexUtils.h` (createIndex/loadIndex)

| stellar-core | Rust | Status |
|--------------|------|--------|
| `DiskIndex::saveToDisk()` | `save_disk_index()` | Full |
| `loadIndex()` | `load_disk_index()` | Full |
| `createIndex()` | `LiveBucketIndex::new()` | Full |
| Version checking on load | `BUCKET_INDEX_VERSION` check | Full |

## Intentional Omissions

Features excluded by design. These are NOT counted against parity %.

| stellar-core Component | Reason |
|------------------------|--------|
| `BucketMergeAdapter.h` | Rust generics eliminate need for C++ template adapter pattern |
| Shadow bucket support in merges | Protocol 23+ only; shadows removed in protocol 12 |
| `TmpDirManager` / lock file | Rust uses `tempfile` crate and OS-level locking |
| Medida metrics library integration | Rust uses custom atomic counters and tracing |
| `NonMovableOrCopyable` base class | Rust ownership system enforces this at compile time |
| `AppConnector` parameter threading | Rust uses direct dependency injection |
| `BUILD_TESTS` conditional compilation | Rust uses `#[cfg(test)]` natively |

## Gaps

Features not yet implemented. These ARE counted against parity %.

| stellar-core Component | Priority | Notes |
|------------------------|----------|-------|
| `BucketManager::getMergeFuture()` / `putMergeFuture()` | Medium | MergeMap exists but not wired into merge workflow |
| `BucketManager::getBloomMissMeter()` / `getBloomLookupMeter()` | Low | Medida-style meter not integrated |
| `BucketManager::loadCompleteHotArchiveState()` (full) | Low | Partial via hot archive iteration |
| `BucketManager::scheduleVerifyReferencedBucketsWork()` (as Work) | Low | Verification exists but not as Work class |
| `BucketInputIterator::seek()` | Low | Position seeking not exposed |
| `EvictionStatistics::submitMetricsAndRestartCycle()` | Low | Simplified eviction stats |

## Architectural Differences

1. **Unified Bucket Type**
   - **stellar-core**: Separate `LiveBucket` and `HotArchiveBucket` classes inheriting from `BucketBase<BucketT, IndexT>` via CRTP, each with distinct index types.
   - **Rust**: Single `Bucket` type with storage modes (InMemory/DiskBacked) for live buckets, separate `HotArchiveBucket` type for hot archive.
   - **Rationale**: Rust does not use CRTP; the unified type with storage modes provides equivalent functionality with simpler code. Hot archive is kept separate because it stores `HotArchiveBucketEntry` instead of `BucketEntry`.

2. **Async Merge Architecture**
   - **stellar-core**: `FutureBucket` wraps `std::shared_future` with background thread pool via `asio::io_context`.
   - **Rust**: `PendingMerge` uses `tokio::task::spawn_blocking` with `oneshot::Receiver` for async merge results, plus a standalone `FutureBucket` type for HAS serialization.
   - **Rationale**: Tokio's blocking thread pool provides equivalent parallelism with better integration into the async runtime.

3. **Merge Deduplication Integration**
   - **stellar-core**: `BucketManager` holds `mLiveBucketFutures` and `mFinishedMerges` (`BucketMergeMap`), automatically deduplicating and reattaching merges.
   - **Rust**: `BucketMergeMap` and `LiveMergeFutures` are implemented and tested but not wired into the `BucketList` merge workflow.
   - **Rationale**: Current approach guards against concurrent duplicates but does not cache completed merge results. Impact is limited to catchup/restart scenarios.

4. **Index Persistence Format**
   - **stellar-core**: Uses Cereal (binary) serialization for `DiskIndex` persistence.
   - **Rust**: Uses bincode serialization with a version header for `.index` files.
   - **Rationale**: Bincode is the Rust equivalent of Cereal for efficient binary serialization.

5. **Snapshot Concurrency Model**
   - **stellar-core**: Uses `std::shared_mutex` with explicit lock annotations (`GUARDED_BY`, `REQUIRES_SHARED`).
   - **Rust**: Uses `parking_lot::RwLock` which provides equivalent semantics with Rust's ownership model enforcing safety.
   - **Rationale**: Rust's type system enforces lock ordering at compile time, eliminating the need for annotation macros.

## Test Coverage

| Area | stellar-core Tests | Rust Tests | Notes |
|------|-------------------|------------|-------|
| BucketTests.cpp | 8 TEST_CASE / 13 SECTION | ~39 #[test] | Merge semantics, hot archive merge |
| BucketListTests.cpp | 17 TEST_CASE / 23 SECTION | ~44 #[test] | Spill, eviction, snapshots |
| BucketManagerTests.cpp | 10 TEST_CASE / 0 SECTION | ~27 #[test] | Lifecycle, persistence, reattachment |
| BucketIndexTests.cpp | 13 TEST_CASE / 10 SECTION | ~21 #[test] | Index types, serialization, cache |
| BucketMergeMapTests.cpp | 1 TEST_CASE / 0 SECTION | ~6 #[test] | Merge deduplication |
| **Total** | **49 TEST_CASE / 46 SECTION** | **~306 #[test]** | Rust tests more granular |

### Test Gaps

- **Concurrent snapshot access during merges**: No explicit thread safety stress test matching stellar-core's `bucketmanager reattach to running merge` test pattern.
- **Large bucket index tests**: stellar-core has dedicated tests for serializing/deserializing large bucket indexes (`serialize bucket indexes`); Rust has persistence tests but fewer edge cases for very large buckets.
- **`maxEntriesToArchive` limiting**: No test verifying eviction respects per-ledger archive limits.
- **BucketManager restart with in-progress merges**: stellar-core tests persistence of `FutureBucket` state across app restart; Rust tests basic persistence but not in-progress merge recovery.

## Parity Calculation

| Category | Count |
|----------|-------|
| Implemented (Full) | 138 |
| Gaps (None + Partial) | 11 |
| Intentional Omissions | 7 |
| **Parity** | **138 / (138 + 11) = 93%** |
