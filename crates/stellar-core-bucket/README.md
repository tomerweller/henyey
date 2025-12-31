# stellar-core-bucket

BucketList implementation for rs-stellar-core.

## Overview

The BucketList is Stellar's core data structure for storing ledger state. It provides:

- Efficient incremental updates as ledgers close
- Merkle tree structure for integrity verification
- Hierarchical organization with multiple levels
- Support for live entries, dead entries, and init entries

## Structure

The BucketList consists of multiple levels (11 by default), where each level contains two buckets:

- **curr**: The current bucket being filled
- **snap**: The snapshot bucket from the previous merge

Lower levels update more frequently, while higher levels contain older data and update less often (similar to a log-structured merge tree).

```
Level 0: [curr] [snap]  <- Updates every ledger
Level 1: [curr] [snap]  <- Updates every 4 ledgers
Level 2: [curr] [snap]  <- Updates every 16 ledgers
Level 3: [curr] [snap]  <- Updates every 64 ledgers
...
Level 10: [curr] [snap] <- Updates every ~1M ledgers
```

## Spill Frequency

- Level 0 spills every ledger
- Level N spills every 2^(2N) ledgers

| Level | Spill Frequency |
|-------|-----------------|
| 0 | Every 1 ledger |
| 1 | Every 4 ledgers |
| 2 | Every 16 ledgers |
| 3 | Every 64 ledgers |
| 4 | Every 256 ledgers |
| 5 | Every 1,024 ledgers |

## Entry Types

| Type | Description |
|------|-------------|
| `LiveEntry` | A live ledger entry |
| `DeadEntry` | A tombstone marking deletion |
| `InitEntry` | Like LiveEntry but with different merge semantics |
| `Metadata` | Bucket metadata (protocol version, etc.) |

## Usage

### Basic Operations

```rust
use stellar_core_bucket::{BucketList, BucketManager};

// Create a bucket manager
let manager = BucketManager::new("/tmp/buckets".into())?;

// Create a new bucket list
let mut bucket_list = BucketList::new();

// Add entries from a closed ledger
let live_entries = vec![/* ledger entries */];
let dead_entries = vec![/* deleted keys */];
bucket_list.add_batch(1, live_entries, dead_entries)?;

// Look up an entry
if let Some(entry) = bucket_list.get(&key)? {
    // Use the entry
}

// Get the bucket list hash for verification
let hash = bucket_list.hash();
```

### Working with Buckets

```rust
use stellar_core_bucket::{Bucket, BucketEntry, BucketManager};

let manager = BucketManager::new(bucket_dir)?;

// Create a bucket with entries
let entries = vec![
    BucketEntry::Live(account_entry),
    BucketEntry::Dead(deleted_key),
];
let bucket = manager.create_bucket(entries)?;

// Get bucket hash
let hash = bucket.hash();

// Check if bucket exists on disk
assert!(manager.bucket_exists(&hash));

// Load bucket from disk
let loaded = manager.load_bucket(&hash)?;
```

### Merging Buckets

```rust
use stellar_core_bucket::{merge_buckets, Bucket};

// Merge two buckets (newer entries shadow older ones)
let merged = merge_buckets(&old_bucket, &new_bucket)?;

// Merge multiple buckets
let merged = merge_multiple(&[bucket1, bucket2, bucket3])?;
```

## Key Types

### BucketList

The main data structure holding all levels:

```rust
use stellar_core_bucket::BucketList;

let bucket_list = BucketList::new();
let hash = bucket_list.hash();
let stats = bucket_list.stats();
```

### BucketManager

Manages bucket storage on disk:

```rust
use stellar_core_bucket::BucketManager;

let manager = BucketManager::new(path)?;

// Create, load, and manage buckets
let bucket = manager.create_bucket(entries)?;
let loaded = manager.load_bucket(&hash)?;
let exists = manager.bucket_exists(&hash);

// Clear cache
manager.clear_cache();
```

### BucketEntry

Individual entries in a bucket:

```rust
use stellar_core_bucket::BucketEntry;

let entry = BucketEntry::Live(ledger_entry);
assert!(entry.is_live());
assert!(!entry.is_dead());

let tombstone = BucketEntry::Dead(ledger_key);
assert!(tombstone.is_dead());
```

## Constants

```rust
use stellar_core_bucket::BUCKET_LIST_LEVELS;

assert_eq!(BUCKET_LIST_LEVELS, 11);
```

## File Format

Buckets are stored as XDR-encoded files with gzip compression. The filename is the hex-encoded SHA-256 hash of the bucket contents.

```
buckets/
  bucket-abc123....xdr.gz
  bucket-def456....xdr.gz
```

## Dependencies

- `stellar-xdr` - XDR types
- `sha2` - Hashing
- `flate2` - Gzip compression

## License

Apache 2.0
