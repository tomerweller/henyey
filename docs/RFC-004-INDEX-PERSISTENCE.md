# RFC-004: Index Persistence

**Status:** Approved  
**Created:** 2026-01-27  
**Target:** Phase 4 of Mainnet Support (Bucket List DB Revamp)  
**Estimated Duration:** 1 week  
**Dependencies:** RFC-003 (BucketListDB Point Lookups) - Required

## Summary

Persist `DiskIndex` structures to `.index` files alongside bucket files, enabling fast startup
without needing to rebuild indexes from scratch. This significantly reduces catchup and restart
time for validators.

## Motivation

### Current Problem (After RFC-003)

Without persistence, every startup requires rebuilding all `DiskIndex` structures:

```
Startup time (mainnet):
- Read ~50 GB of bucket files
- Build range indexes
- Build bloom filters
- Time: ~30-60 minutes
```

### C++ Architecture (What We're Matching)

C++ stellar-core persists `DiskIndex` to `.index` files:

```cpp
// File naming: bucket-{hash}.index
std::filesystem::path canonicalName = bm.bucketIndexFilename(hash);
// e.g., "buckets/bucket-ab12cd34.index"

// Serialization format: cereal binary archive
cereal::BinaryOutputArchive ar(out);
ar(mData);  // Writes: version, pageSize, keysToOffset, filter, counters, typeRanges
```

Key details:
- Only `DiskIndex` is persisted (not `InMemoryIndex`)
- Uses version field for compatibility checking
- Atomic writes via temp file + rename
- Validates version and pageSize on load

### Benefits

| Metric | Without Persistence | With Persistence |
|--------|---------------------|------------------|
| Cold start | 30-60 min | 1-2 min |
| After crash | 30-60 min | 1-2 min |
| Index memory | Same | Same |

## Design

### File Format

```
bucket-{hash}.index
├── header
│   ├── version: u32 (BUCKET_INDEX_VERSION = 6)
│   └── page_size: u64
└── data
    ├── keys_to_offset: Vec<(RangeEntry, u64)>
    ├── filter: Option<BinaryFuse16>
    ├── asset_to_pool_ids: HashMap<Asset, Vec<PoolId>>
    ├── counters: BucketEntryCounters
    └── type_ranges: HashMap<LedgerEntryType, (u64, u64)>
```

### Serialization Format

Use `bincode` for Rust serialization (fast, compact, similar to cereal):

```rust
use serde::{Serialize, Deserialize};

pub const BUCKET_INDEX_VERSION: u32 = 6;

#[derive(Serialize, Deserialize)]
struct IndexHeader {
    version: u32,
    page_size: u64,
}

#[derive(Serialize, Deserialize)]
struct DiskIndexData {
    keys_to_offset: Vec<(RangeEntry, u64)>,
    filter: Option<SerializableBinaryFuse16>,
    asset_to_pool_ids: HashMap<Asset, Vec<PoolId>>,
    counters: BucketEntryCounters,
    type_ranges: HashMap<LedgerEntryType, (u64, u64)>,
}
```

### Save Implementation

```rust
impl DiskIndex {
    /// Save index to disk for future fast loading.
    pub fn save_to_disk(
        &self,
        bucket_manager: &BucketManager,
        bucket_hash: &Hash,
    ) -> Result<(), BucketError> {
        if !bucket_manager.config().bucketlist_db_persist_index {
            return Ok(());
        }
        
        let tmp_path = bucket_manager.tmp_dir().join(
            format!("bucket-{}.index.tmp", hex::encode(bucket_hash))
        );
        let final_path = bucket_manager.bucket_index_path(bucket_hash);
        
        // Write to temp file
        {
            let file = File::create(&tmp_path)?;
            let mut writer = BufWriter::new(file);
            
            // Write header first (for fast validation on load)
            let header = IndexHeader {
                version: BUCKET_INDEX_VERSION,
                page_size: self.page_size,
            };
            bincode::serialize_into(&mut writer, &header)?;
            
            // Write data
            let data = DiskIndexData {
                keys_to_offset: self.keys_to_offset.clone(),
                filter: self.filter.as_ref().map(|f| f.to_serializable()),
                asset_to_pool_ids: self.asset_to_pool_ids.clone(),
                counters: self.counters.clone(),
                type_ranges: self.type_ranges.clone(),
            };
            bincode::serialize_into(&mut writer, &data)?;
            
            writer.flush()?;
        }
        
        // Atomic rename
        std::fs::rename(&tmp_path, &final_path).map_err(|e| {
            // Retry once after short delay (race condition workaround)
            std::thread::sleep(Duration::from_secs(1));
            std::fs::rename(&tmp_path, &final_path)
        })?;
        
        tracing::debug!(
            bucket_hash = %hex::encode(bucket_hash),
            path = %final_path.display(),
            "Saved bucket index"
        );
        
        Ok(())
    }
}
```

### Load Implementation

```rust
impl DiskIndex {
    /// Try to load index from disk.
    ///
    /// Returns `None` if:
    /// - Index file doesn't exist
    /// - Version mismatch
    /// - PageSize mismatch
    /// - Deserialization error
    pub fn load_from_disk(
        bucket_manager: &BucketManager,
        bucket_hash: &Hash,
        expected_page_size: u64,
    ) -> Result<Option<Self>, BucketError> {
        let path = bucket_manager.bucket_index_path(bucket_hash);
        
        if !path.exists() {
            return Ok(None);
        }
        
        let file = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut reader = BufReader::new(file);
        
        // Read and validate header
        let header: IndexHeader = match bincode::deserialize_from(&mut reader) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to read index header, will rebuild"
                );
                return Ok(None);
            }
        };
        
        // Version check
        if header.version != BUCKET_INDEX_VERSION {
            tracing::info!(
                path = %path.display(),
                stored_version = header.version,
                expected_version = BUCKET_INDEX_VERSION,
                "Index version mismatch, will rebuild"
            );
            // Delete outdated file
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }
        
        // PageSize check
        if header.page_size != expected_page_size {
            tracing::info!(
                path = %path.display(),
                stored_page_size = header.page_size,
                expected_page_size = expected_page_size,
                "Index page size mismatch, will rebuild"
            );
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }
        
        // Load data
        let data: DiskIndexData = match bincode::deserialize_from(&mut reader) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Failed to deserialize index, will rebuild"
                );
                let _ = std::fs::remove_file(&path);
                return Ok(None);
            }
        };
        
        Ok(Some(Self {
            page_size: header.page_size,
            keys_to_offset: data.keys_to_offset,
            filter: data.filter.map(|f| f.to_filter()),
            asset_to_pool_ids: data.asset_to_pool_ids,
            counters: data.counters,
            type_ranges: data.type_ranges,
            bucket_path: bucket_manager.bucket_path(bucket_hash),
        }))
    }
}
```

### Integration with BucketIndex Factory

```rust
impl BucketIndex {
    /// Create or load index for a bucket.
    pub fn new(
        bucket_manager: &BucketManager,
        bucket_path: &Path,
        bucket_hash: &Hash,
        config: &Config,
    ) -> Result<Self, BucketError> {
        let bucket_size = std::fs::metadata(bucket_path)?.len();
        let cutoff = config.bucketlist_db_index_cutoff_mb as u64 * 1024 * 1024;
        
        if bucket_size < cutoff {
            // Small bucket: always build InMemoryIndex (not persisted)
            Ok(BucketIndex::InMemory(InMemoryIndex::build(bucket_path)?))
        } else {
            // Large bucket: try to load from disk first
            let page_size = DiskIndex::compute_page_size(config, bucket_size);
            
            if let Some(index) = DiskIndex::load_from_disk(
                bucket_manager,
                bucket_hash,
                page_size,
            )? {
                tracing::debug!(
                    bucket_hash = %hex::encode(bucket_hash),
                    "Loaded index from disk"
                );
                return Ok(BucketIndex::Disk(index));
            }
            
            // Build new index
            let index = DiskIndex::build(bucket_path, config)?;
            
            // Save for future use
            index.save_to_disk(bucket_manager, bucket_hash)?;
            
            Ok(BucketIndex::Disk(index))
        }
    }
}
```

### BinaryFuse16 Serialization

The bloom filter needs custom serialization:

```rust
#[derive(Serialize, Deserialize)]
pub struct SerializableBinaryFuse16 {
    seed: u64,
    segment_length: u32,
    segment_length_mask: u32,
    segment_count: u32,
    segment_count_length: u32,
    fingerprints: Vec<u16>,
}

impl SerializableBinaryFuse16 {
    pub fn from_filter(filter: &BinaryFuse16) -> Self {
        Self {
            seed: filter.seed,
            segment_length: filter.segment_length,
            segment_length_mask: filter.segment_length_mask,
            segment_count: filter.segment_count,
            segment_count_length: filter.segment_count_length,
            fingerprints: filter.fingerprints.clone(),
        }
    }
    
    pub fn to_filter(self) -> BinaryFuse16 {
        BinaryFuse16 {
            seed: self.seed,
            segment_length: self.segment_length,
            segment_length_mask: self.segment_length_mask,
            segment_count: self.segment_count,
            segment_count_length: self.segment_count_length,
            fingerprints: self.fingerprints,
        }
    }
}
```

### Cleanup of Orphaned Index Files

When buckets are deleted, their index files should be cleaned up:

```rust
impl BucketManager {
    /// Clean up index files for buckets that no longer exist.
    pub fn cleanup_orphaned_indexes(&self) -> Result<(), BucketError> {
        let bucket_dir = self.bucket_dir();
        
        for entry in std::fs::read_dir(&bucket_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension() == Some("index".as_ref()) {
                // Extract hash from filename
                let stem = path.file_stem().and_then(|s| s.to_str());
                if let Some(stem) = stem {
                    if stem.starts_with("bucket-") {
                        let hash_str = &stem[7..]; // Remove "bucket-" prefix
                        let bucket_path = bucket_dir.join(format!("bucket-{}.xdr", hash_str));
                        
                        if !bucket_path.exists() {
                            tracing::info!(
                                path = %path.display(),
                                "Removing orphaned index file"
                            );
                            std::fs::remove_file(&path)?;
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
}
```

## Configuration

```toml
[bucketlist_db]
# Whether to persist DiskIndex to .index files
persist_index = true
```

## Implementation Plan

### Week 1

| Day | Task |
|-----|------|
| 1 | Add serde derives to DiskIndex data structures |
| 2 | Implement `save_to_disk()` with atomic writes |
| 3 | Implement `load_from_disk()` with validation |
| 4 | Integrate with BucketIndex factory |
| 5 | Add orphan cleanup, unit tests |

## Files to Create/Modify

| File | Action |
|------|--------|
| `crates/stellar-core-bucket/src/disk_index.rs` | Add save/load methods |
| `crates/stellar-core-bucket/src/bucket_index.rs` | Integrate persistence |
| `crates/stellar-core-bucket/src/bucket_manager.rs` | Add `bucket_index_path()` |
| `crates/stellar-core-bucket/src/serialization.rs` | **Create** - BinaryFuse16 serde |

## Disk Space Impact

| Bucket Size | Index File Size | Ratio |
|-------------|-----------------|-------|
| 100 MB | ~2 MB | 2% |
| 1 GB | ~20 MB | 2% |
| 10 GB | ~200 MB | 2% |
| **Total (mainnet)** | **~1 GB** | **2%** |

Index files add approximately 2% overhead to bucket storage.

## Startup Time Impact

| Operation | Without Persistence | With Persistence |
|-----------|---------------------|------------------|
| Load 1 GB bucket index | ~30 sec | ~1 sec |
| Load all indexes (mainnet) | ~30 min | ~2 min |
| **Total cold start** | **~45 min** | **~5 min** |

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Corrupt index file | Version check + rebuild on error |
| Stale index after config change | PageSize check triggers rebuild |
| Disk space | Only 2% overhead; cleanup orphans |
| Migration from older version | Version mismatch triggers rebuild |

## Testing Strategy

1. **Unit tests**: Save/load round-trip
2. **Version tests**: Correct behavior on version mismatch
3. **Corruption tests**: Graceful handling of corrupt files
4. **Integration tests**: Full startup with persisted indexes
5. **Performance tests**: Measure startup time improvement

## Success Criteria

1. Indexes persist correctly across restarts
2. Version/pageSize mismatches trigger rebuild
3. Corrupt files are handled gracefully
4. Startup time reduced by 80%+
5. No regression in index lookup performance

## References

- C++ Implementation: `.upstream-v25/src/bucket/DiskIndex.cpp` (lines 323-372)
- C++ Index Loading: `.upstream-v25/src/bucket/BucketIndexUtils.cpp`
- RFC-003: BucketListDB Point Lookups
