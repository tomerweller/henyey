# History Module Specification

**Crate**: `stellar-core-history`
**stellar-core mapping**: `src/history/`

## 1. Overview

The history module handles:
- Downloading historical data from archives for catchup
- Publishing checkpoints to archives (for validators)
- Verifying archive integrity
- Managing the catchup process

## 2. stellar-core Reference

In stellar-core, the history module (`src/history/`) contains:
- `HistoryArchive.h/cpp` - Archive interface
- `HistoryArchiveManager.h/cpp` - Multi-archive management
- `HistoryManager.h/cpp` - Main coordination
- `FileTransferInfo.h/cpp` - Transfer tracking
- `StateSnapshot.h/cpp` - Checkpoint snapshots
- Various `*Work.h/cpp` files - Async work items

### 2.1 Archive Structure

```
archive/
├── .well-known/
│   └── stellar-history.json     # Root HAS (History Archive State)
├── history/
│   └── ww/xx/yy/
│       └── history-wwxxyyzz.json
├── ledger/
│   └── ww/xx/yy/
│       └── ledger-wwxxyyzz.xdr.gz
├── transactions/
│   └── ww/xx/yy/
│       └── transactions-wwxxyyzz.xdr.gz
├── results/
│   └── ww/xx/yy/
│       └── results-wwxxyyzz.xdr.gz
├── scp/
│   └── ww/xx/yy/
│       └── scp-wwxxyyzz.xdr.gz
└── bucket/
    └── pp/qq/rr/
        └── bucket-[64-hex-chars].xdr.gz
```

### 2.2 Checkpoint Frequency

- Checkpoints occur every 64 ledgers
- Checkpoint ledger sequence: `(seq + 1) % 64 == 0`
- First checkpoint: ledger 63
- Second checkpoint: ledger 127

## 3. Rust Implementation

### 3.1 Dependencies

```toml
[dependencies]
stellar-xdr = { version = "25.0.0", features = ["std", "curr", "serde_json"] }
stellar-core-crypto = { path = "../stellar-core-crypto" }
stellar-core-bucket = { path = "../stellar-core-bucket" }

# HTTP client - pure Rust
reqwest = { version = "0.11", default-features = false, features = ["rustls-tls", "gzip", "json"] }

# Compression - pure Rust
flate2 = { version = "1.0", default-features = false, features = ["rust_backend"] }

# Async runtime
tokio = { version = "1", features = ["fs", "io-util", "time", "sync"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Utilities
thiserror = "1"
tracing = "0.1"
url = "2"
futures = "0.3"
async-trait = "0.1"
tempfile = "3"
```

### 3.2 Module Structure

```
stellar-core-history/
├── src/
│   ├── lib.rs
│   ├── archive.rs           # Archive client
│   ├── archive_state.rs     # HAS parsing
│   ├── checkpoint.rs        # Checkpoint handling
│   ├── catchup.rs           # Catchup orchestration
│   ├── publish.rs           # Archive publishing
│   ├── download.rs          # File downloads
│   ├── verify.rs            # Integrity verification
│   ├── work/
│   │   ├── mod.rs
│   │   ├── download_work.rs
│   │   ├── verify_work.rs
│   │   ├── apply_work.rs
│   │   └── publish_work.rs
│   └── error.rs
└── tests/
```

### 3.3 Core Types

#### History Archive State (HAS)

```rust
use serde::{Deserialize, Serialize};

/// History Archive State - the root JSON file
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryArchiveState {
    /// Format version
    pub version: u32,

    /// Server identifier (optional)
    #[serde(default)]
    pub server: Option<String>,

    /// Current ledger sequence
    pub current_ledger: u32,

    /// Network passphrase (optional)
    #[serde(default)]
    pub network_passphrase: Option<String>,

    /// Bucket list state
    pub current_buckets: Vec<HASBucketLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HASBucketLevel {
    /// Current bucket hash (hex)
    pub curr: String,
    /// Snapshot bucket hash (hex)
    pub snap: String,
    /// Next bucket state (for async merge)
    #[serde(default)]
    pub next: HASBucketNext,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HASBucketNext {
    pub state: u32,
    #[serde(default)]
    pub output: Option<String>,
}

impl HistoryArchiveState {
    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self, HistoryError> {
        serde_json::from_str(json).map_err(HistoryError::from)
    }

    /// Get all bucket hashes referenced in this HAS
    pub fn all_bucket_hashes(&self) -> Vec<Hash256> {
        let mut hashes = Vec::new();
        for level in &self.current_buckets {
            if !level.curr.is_empty() && level.curr != "0".repeat(64) {
                if let Ok(h) = Hash256::from_hex(&level.curr) {
                    hashes.push(h);
                }
            }
            if !level.snap.is_empty() && level.snap != "0".repeat(64) {
                if let Ok(h) = Hash256::from_hex(&level.snap) {
                    hashes.push(h);
                }
            }
        }
        hashes
    }

    /// Get the checkpoint ledger for this HAS
    pub fn checkpoint_ledger(&self) -> u32 {
        self.current_ledger
    }
}
```

#### History Archive Client

```rust
use url::Url;
use reqwest::Client;

/// Client for accessing a history archive
pub struct HistoryArchive {
    /// Base URL of the archive
    base_url: Url,
    /// HTTP client
    client: Client,
    /// Archive name (for logging)
    name: String,
}

impl HistoryArchive {
    pub fn new(base_url: &str, name: &str) -> Result<Self, HistoryError> {
        let base_url = Url::parse(base_url)?;
        let client = Client::builder()
            .gzip(true)
            .timeout(std::time::Duration::from_secs(60))
            .build()?;

        Ok(Self {
            base_url,
            client,
            name: name.to_string(),
        })
    }

    /// Fetch the root HAS
    pub async fn get_root_has(&self) -> Result<HistoryArchiveState, HistoryError> {
        let url = self.base_url.join(".well-known/stellar-history.json")?;
        let response = self.client.get(url).send().await?;
        let text = response.text().await?;
        HistoryArchiveState::from_json(&text)
    }

    /// Fetch HAS for a specific checkpoint
    pub async fn get_checkpoint_has(&self, ledger: u32) -> Result<HistoryArchiveState, HistoryError> {
        let path = checkpoint_path("history", ledger, "json");
        let url = self.base_url.join(&path)?;
        let response = self.client.get(url).send().await?;
        let text = response.text().await?;
        HistoryArchiveState::from_json(&text)
    }

    /// Download ledger headers for a checkpoint
    pub async fn get_ledger_headers(&self, ledger: u32) -> Result<Vec<LedgerHeaderHistoryEntry>, HistoryError> {
        let path = checkpoint_path("ledger", ledger, "xdr.gz");
        let data = self.download_xdr_gz(&path).await?;
        parse_xdr_stream(&data)
    }

    /// Download transactions for a checkpoint
    pub async fn get_transactions(&self, ledger: u32) -> Result<Vec<TransactionHistoryEntry>, HistoryError> {
        let path = checkpoint_path("transactions", ledger, "xdr.gz");
        let data = self.download_xdr_gz(&path).await?;
        parse_xdr_stream(&data)
    }

    /// Download transaction results for a checkpoint
    pub async fn get_results(&self, ledger: u32) -> Result<Vec<TransactionHistoryResultEntry>, HistoryError> {
        let path = checkpoint_path("results", ledger, "xdr.gz");
        let data = self.download_xdr_gz(&path).await?;
        parse_xdr_stream(&data)
    }

    /// Download a bucket file
    pub async fn get_bucket(&self, hash: &Hash256) -> Result<Vec<u8>, HistoryError> {
        let path = bucket_path(hash);
        self.download_xdr_gz(&path).await
    }

    async fn download_xdr_gz(&self, path: &str) -> Result<Vec<u8>, HistoryError> {
        let url = self.base_url.join(path)?;
        tracing::debug!(url = %url, "Downloading");

        let response = self.client.get(url.clone()).send().await?;

        if !response.status().is_success() {
            return Err(HistoryError::NotFound(url.to_string()));
        }

        let compressed = response.bytes().await?;
        decompress_gzip(&compressed)
    }
}

/// Generate checkpoint file path
fn checkpoint_path(category: &str, ledger: u32, ext: &str) -> String {
    let checkpoint = (ledger / 64) * 64 + 63; // Round to checkpoint
    let hex = format!("{:08x}", checkpoint);
    format!(
        "{}/{}/{}/{}/{}-{}.{}",
        category,
        &hex[0..2],
        &hex[2..4],
        &hex[4..6],
        category,
        hex,
        ext
    )
}

/// Generate bucket file path
fn bucket_path(hash: &Hash256) -> String {
    let hex = hex::encode(hash.as_bytes());
    format!(
        "bucket/{}/{}/{}/bucket-{}.xdr.gz",
        &hex[0..2],
        &hex[2..4],
        &hex[4..6],
        hex
    )
}
```

### 3.4 Catchup Process

```rust
use stellar_core_bucket::BucketList;
use stellar_core_ledger::LedgerManager;

/// Catchup mode
#[derive(Debug, Clone, Copy)]
pub enum CatchupMode {
    /// Catch up to a specific ledger, keeping only minimal history
    Minimal { target_ledger: u32 },
    /// Catch up and keep recent history
    Recent { count: u32 },
    /// Full catchup with all history
    Complete,
}

/// Orchestrates the catchup process
pub struct CatchupManager {
    archives: Vec<HistoryArchive>,
    bucket_manager: Arc<BucketManager>,
    work_dir: PathBuf,
}

impl CatchupManager {
    /// Perform catchup to target ledger
    pub async fn catchup(
        &self,
        mode: CatchupMode,
        current_ledger: u32,
    ) -> Result<CatchupResult, HistoryError> {
        let target = match mode {
            CatchupMode::Minimal { target_ledger } => target_ledger,
            CatchupMode::Recent { count } => {
                let has = self.get_latest_has().await?;
                has.current_ledger
            }
            CatchupMode::Complete => {
                return Err(HistoryError::UnsupportedMode("Complete catchup not supported (Protocol 23+ only)".into()));
            }
        };

        tracing::info!(
            current = current_ledger,
            target = target,
            "Starting catchup"
        );

        // Find the checkpoint we need
        let checkpoint = self.find_checkpoint(target).await?;

        // Download and verify checkpoint HAS
        let has = self.download_and_verify_has(checkpoint).await?;

        // Download all required buckets
        let buckets = self.download_buckets(&has).await?;

        // Apply buckets to build initial state
        let bucket_list = self.apply_buckets(&has, &buckets).await?;

        // Download and replay ledgers from checkpoint to target
        let ledger_range = checkpoint..=target;
        for ledger_seq in ledger_range {
            let checkpoint_seq = (ledger_seq / 64) * 64 + 63;
            if ledger_seq <= checkpoint_seq {
                // Download checkpoint data
                let headers = self.download_ledger_headers(checkpoint_seq).await?;
                let txs = self.download_transactions(checkpoint_seq).await?;
                let results = self.download_results(checkpoint_seq).await?;

                // Replay ledgers in this checkpoint
                for header in &headers {
                    if header.header.ledger_seq >= current_ledger &&
                       header.header.ledger_seq <= target {
                        self.replay_ledger(header, &txs, &results).await?;
                    }
                }
            }
        }

        Ok(CatchupResult {
            initial_ledger: checkpoint,
            final_ledger: target,
            bucket_list,
        })
    }

    async fn get_latest_has(&self) -> Result<HistoryArchiveState, HistoryError> {
        // Try each archive until one succeeds
        for archive in &self.archives {
            match archive.get_root_has().await {
                Ok(has) => return Ok(has),
                Err(e) => {
                    tracing::warn!(archive = %archive.name, error = %e, "Failed to get HAS");
                    continue;
                }
            }
        }
        Err(HistoryError::NoArchiveAvailable)
    }

    async fn download_buckets(&self, has: &HistoryArchiveState) -> Result<HashMap<Hash256, Vec<u8>>, HistoryError> {
        let hashes = has.all_bucket_hashes();
        let mut buckets = HashMap::new();

        // Download in parallel
        let downloads: Vec<_> = hashes.iter().map(|hash| {
            let archives = self.archives.clone();
            let hash = *hash;
            async move {
                for archive in &archives {
                    match archive.get_bucket(&hash).await {
                        Ok(data) => return Ok((hash, data)),
                        Err(e) => {
                            tracing::warn!(
                                hash = %hex::encode(hash.as_bytes()),
                                error = %e,
                                "Failed to download bucket"
                            );
                            continue;
                        }
                    }
                }
                Err(HistoryError::BucketNotFound(hash))
            }
        }).collect();

        let results = futures::future::join_all(downloads).await;
        for result in results {
            let (hash, data) = result?;
            buckets.insert(hash, data);
        }

        Ok(buckets)
    }
}

pub struct CatchupResult {
    pub initial_ledger: u32,
    pub final_ledger: u32,
    pub bucket_list: BucketList,
}
```

### 3.5 Verification

```rust
/// Verify checkpoint integrity
pub struct CheckpointVerifier {
    network_passphrase: String,
}

impl CheckpointVerifier {
    /// Verify a ledger header chain
    pub fn verify_header_chain(
        &self,
        headers: &[LedgerHeaderHistoryEntry],
    ) -> Result<(), HistoryError> {
        for window in headers.windows(2) {
            let prev = &window[0];
            let curr = &window[1];

            // Verify sequence
            if curr.header.ledger_seq != prev.header.ledger_seq + 1 {
                return Err(HistoryError::InvalidSequence {
                    expected: prev.header.ledger_seq + 1,
                    got: curr.header.ledger_seq,
                });
            }

            // Verify hash chain
            let expected_prev_hash = prev.hash()?;
            if curr.header.previous_ledger_hash != expected_prev_hash {
                return Err(HistoryError::InvalidPreviousHash {
                    ledger: curr.header.ledger_seq,
                });
            }
        }
        Ok(())
    }

    /// Verify transaction results match header
    pub fn verify_transaction_set(
        &self,
        header: &LedgerHeader,
        txs: &[TransactionHistoryEntry],
        results: &[TransactionHistoryResultEntry],
    ) -> Result<(), HistoryError> {
        // Build transaction set and compute hash
        let tx_set_hash = compute_tx_set_hash(txs)?;

        if header.scp_value.tx_set_hash != tx_set_hash {
            return Err(HistoryError::InvalidTxSetHash {
                ledger: header.ledger_seq,
            });
        }

        Ok(())
    }
}
```

### 3.6 Publishing (for Validators)

```rust
/// Publish checkpoints to history archive
pub struct HistoryPublisher {
    archive_put_cmd: String, // Command template for puts
    work_dir: PathBuf,
}

impl HistoryPublisher {
    /// Publish a checkpoint
    pub async fn publish_checkpoint(
        &self,
        ledger_seq: u32,
        has: &HistoryArchiveState,
        bucket_list: &BucketList,
        ledger_headers: &[LedgerHeaderHistoryEntry],
        transactions: &[TransactionHistoryEntry],
        results: &[TransactionHistoryResultEntry],
    ) -> Result<(), HistoryError> {
        // Only publish at checkpoint boundaries
        if (ledger_seq + 1) % 64 != 0 {
            return Err(HistoryError::NotCheckpointLedger(ledger_seq));
        }

        // Write files to work directory
        let has_path = self.write_has(ledger_seq, has).await?;
        let ledger_path = self.write_ledgers(ledger_seq, ledger_headers).await?;
        let tx_path = self.write_transactions(ledger_seq, transactions).await?;
        let results_path = self.write_results(ledger_seq, results).await?;

        // Upload new bucket files
        for hash in has.all_bucket_hashes() {
            if let Some(bucket) = bucket_list.get_bucket(&hash) {
                self.upload_bucket(&hash, bucket).await?;
            }
        }

        // Upload checkpoint files
        self.upload_file(&has_path, &checkpoint_path("history", ledger_seq, "json")).await?;
        self.upload_file(&ledger_path, &checkpoint_path("ledger", ledger_seq, "xdr.gz")).await?;
        self.upload_file(&tx_path, &checkpoint_path("transactions", ledger_seq, "xdr.gz")).await?;
        self.upload_file(&results_path, &checkpoint_path("results", ledger_seq, "xdr.gz")).await?;

        // Update root HAS (atomic commit point)
        self.upload_file(&has_path, ".well-known/stellar-history.json").await?;

        Ok(())
    }
}
```

## 4. Testnet Archives

```rust
pub mod testnet {
    pub const ARCHIVE_URLS: &[&str] = &[
        "https://history.stellar.org/prd/core-testnet/core_testnet_001",
        "https://history.stellar.org/prd/core-testnet/core_testnet_002",
        "https://history.stellar.org/prd/core-testnet/core_testnet_003",
    ];

    pub const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
}
```

## 5. Error Types

```rust
#[derive(Error, Debug)]
pub enum HistoryError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bucket not found: {0}")]
    BucketNotFound(Hash256),

    #[error("No archive available")]
    NoArchiveAvailable,

    #[error("Invalid sequence: expected {expected}, got {got}")]
    InvalidSequence { expected: u32, got: u32 },

    #[error("Invalid previous hash at ledger {ledger}")]
    InvalidPreviousHash { ledger: u32 },

    #[error("Invalid tx set hash at ledger {ledger}")]
    InvalidTxSetHash { ledger: u32 },

    #[error("Not a checkpoint ledger: {0}")]
    NotCheckpointLedger(u32),

    #[error("Unsupported mode: {0}")]
    UnsupportedMode(String),
}
```

## 6. Tests to Port from stellar-core

From `src/history/test/`:
- Archive URL generation
- HAS parsing and serialization
- Checkpoint verification
- Bucket download and verification
- Catchup simulation
- Publish workflow
