# stellar-core-history

History archive and catchup for rs-stellar-core.

## Overview

This crate handles interaction with Stellar history archives, enabling:

- Downloading ledger history from archives
- Catching up from archives (downloading and applying history)
- Verifying history integrity via hash chains
- Managing multiple archive sources for redundancy

## History Archive Structure

History archives contain:

- **Ledger headers** - Organized in checkpoints (every 64 ledgers)
- **Transaction sets** - Transactions for each ledger
- **Transaction results** - Results for each transaction
- **Bucket files** - BucketList state snapshots
- **SCP messages** - Consensus verification data

## Checkpoints

Stellar organizes history into checkpoints of 64 ledgers:

| Checkpoint | Ledgers |
|------------|---------|
| 63 | 0-63 |
| 127 | 64-127 |
| 191 | 128-191 |
| 255 | 192-255 |

## Usage

### Connecting to Archives

```rust
use stellar_core_history::HistoryArchive;

// Connect to a testnet archive
let archive = HistoryArchive::new(
    "https://history.stellar.org/prd/core-testnet/core_testnet_001"
)?;

// Get the current archive state
let has = archive.get_root_has().await?;
println!("Current ledger: {}", has.current_ledger);

// Get all bucket hashes needed for catchup
let buckets = has.all_bucket_hashes();
println!("Need {} buckets", buckets.len());
```

### Downloading Data

```rust
use stellar_core_history::HistoryArchive;

let archive = HistoryArchive::new(url)?;

// Download ledger headers for a checkpoint
let headers = archive.get_ledger_headers(63).await?;

// Download transactions
let transactions = archive.get_transactions(63).await?;

// Download a bucket
let bucket_data = archive.get_bucket(&bucket_hash).await?;
```

### Managing Multiple Archives

```rust
use stellar_core_history::HistoryManager;

// Create manager with multiple archives for redundancy
let manager = HistoryManager::from_urls(&[
    "https://history.stellar.org/prd/core-testnet/core_testnet_001",
    "https://history.stellar.org/prd/core-testnet/core_testnet_002",
    "https://history.stellar.org/prd/core-testnet/core_testnet_003",
])?;

// Automatically tries each archive on failure
let has = manager.get_root_has().await?;
```

### Catchup

```rust
use stellar_core_history::{CatchupManager, CatchupOptions, CatchupMode};

let options = CatchupOptions {
    target: CatchupTarget::Current,
    mode: CatchupMode::Minimal,
    verify: true,
    parallelism: 8,
};

let mut catchup = CatchupManager::new(archives, bucket_manager, options);
let result = catchup.run().await?;

println!("Caught up to ledger {}", result.ledger_seq);
```

For pre-downloaded checkpoint data (for example, via `stellar-core-historywork`),
use `CheckpointData` with `catchup_to_ledger_with_checkpoint_data` (includes
SCP history when available).

Ledger replay currently re-executes transaction sets against the bucket list
for post-checkpoint ledgers.

### Verification

```rust
use stellar_core_history::verify;

// Verify header chain
verify::verify_header_chain(&headers)?;

// Verify bucket hash
verify::verify_bucket_hash(&bucket_data, &expected_hash)?;

// Verify HAS structure
verify::verify_has_structure(&has)?;
```

## Catchup Modes

| Mode | Description |
|------|-------------|
| `Minimal` | Download only latest state (fastest) |
| `Complete` | Download full history from genesis |
| `Recent(n)` | Download last N ledgers of history |

## Checkpoint Utilities

```rust
use stellar_core_history::checkpoint;

// Get checkpoint containing a ledger
let cp = checkpoint::checkpoint_containing(100); // Returns 127

// Check if ledger is a checkpoint
let is_cp = checkpoint::is_checkpoint_ledger(127); // true

// Get next checkpoint
let next = checkpoint::next_checkpoint(100); // Returns 127

// Get checkpoint range
let (start, end) = checkpoint::checkpoint_range(127); // (64, 127)
```

## Key Types

### HistoryArchiveState (HAS)

Contains the state of an archive at a checkpoint:

```rust
let has = archive.get_root_has().await?;

// Current ledger sequence
let seq = has.current_ledger;

// All bucket hashes for this state
let buckets = has.all_bucket_hashes();
```

### CatchupResult

Result of a successful catchup:

```rust
let result = catchup.run().await?;

println!("Ledger: {}", result.ledger_seq);
println!("Hash: {}", result.ledger_hash);
println!("Buckets downloaded: {}", result.buckets_downloaded);
println!("Ledgers applied: {}", result.ledgers_applied);
```

## Archive URLs

### Testnet

```
https://history.stellar.org/prd/core-testnet/core_testnet_001
https://history.stellar.org/prd/core-testnet/core_testnet_002
https://history.stellar.org/prd/core-testnet/core_testnet_003
```

### Mainnet

```
https://history.stellar.org/prd/core-live/core_live_001
https://history.stellar.org/prd/core-live/core_live_002
https://history.stellar.org/prd/core-live/core_live_003
```

## Dependencies

- `reqwest` - HTTP client
- `stellar-xdr` - XDR types
- `flate2` - Gzip decompression
- `sha2` - Hash verification

## License

Apache 2.0
