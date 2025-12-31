# Ledger Module Specification

**Crate**: `stellar-core-ledger`
**stellar-core mapping**: `src/ledger/`

## 1. Overview

The ledger module manages:
- Ledger state (current ledger header, state hash)
- Ledger closing (applying transaction sets)
- Ledger entry management (CRUD operations)
- State synchronization

## 2. stellar-core Reference

In stellar-core, the ledger module (`src/ledger/`) contains:
- `LedgerManager.h/cpp` - Main ledger coordinator
- `LedgerCloseData.h/cpp` - Close data structure
- `LedgerDelta.h/cpp` - Ledger state changes
- `LedgerHeader.h/cpp` - Header utilities
- `LedgerSnapshot.h/cpp` - Point-in-time snapshot
- `LedgerTxn.h/cpp` - Transaction on ledger state

## 3. Rust Implementation

### 3.1 Dependencies

```toml
[dependencies]
stellar-xdr = { version = "25.0.0", features = ["std", "curr"] }
stellar-core-crypto = { path = "../stellar-core-crypto" }
stellar-core-bucket = { path = "../stellar-core-bucket" }
stellar-core-db = { path = "../stellar-core-db" }
stellar-core-tx = { path = "../stellar-core-tx" }

# Soroban
soroban-env-host = "23"

# Utilities
thiserror = "1"
tracing = "0.1"
parking_lot = "0.12"
```

### 3.2 Module Structure

```
stellar-core-ledger/
├── src/
│   ├── lib.rs
│   ├── ledger_manager.rs    # Main coordinator
│   ├── ledger_header.rs     # Header utilities
│   ├── ledger_close.rs      # Closing logic
│   ├── ledger_delta.rs      # State changes
│   ├── ledger_txn.rs        # State transaction
│   ├── ledger_entry.rs      # Entry operations
│   ├── snapshot.rs          # Point-in-time snapshot
│   └── error.rs
└── tests/
```

### 3.3 Core Types

#### LedgerManager

```rust
use stellar_xdr::curr::{LedgerHeader, LedgerEntry, LedgerKey};
use stellar_core_bucket::BucketList;
use stellar_core_db::Database;

/// Main ledger coordinator
pub struct LedgerManager {
    /// Current ledger header
    current_header: parking_lot::RwLock<LedgerHeader>,

    /// Bucket list for state
    bucket_list: parking_lot::RwLock<BucketList>,

    /// Database for SQL storage
    database: Arc<Database>,

    /// Bucket manager
    bucket_manager: Arc<BucketManager>,

    /// Network passphrase
    network_passphrase: String,

    /// Protocol version
    protocol_version: u32,
}

impl LedgerManager {
    pub fn new(
        database: Arc<Database>,
        bucket_manager: Arc<BucketManager>,
        network_passphrase: String,
    ) -> Self {
        Self {
            current_header: parking_lot::RwLock::new(LedgerHeader::default()),
            bucket_list: parking_lot::RwLock::new(BucketList::new()),
            database,
            bucket_manager,
            network_passphrase,
            protocol_version: 23,
        }
    }

    /// Initialize from a history archive state (for catchup)
    pub async fn initialize_from_has(
        &self,
        has: &HistoryArchiveState,
        buckets: &HashMap<Hash256, Vec<u8>>,
    ) -> Result<(), LedgerError> {
        // Build bucket list from HAS
        let bucket_list = self.build_bucket_list(has, buckets).await?;
        *self.bucket_list.write() = bucket_list;

        tracing::info!(
            ledger = has.current_ledger,
            "Initialized ledger from history archive"
        );

        Ok(())
    }

    /// Get current ledger sequence
    pub fn current_ledger_seq(&self) -> u32 {
        self.current_header.read().ledger_seq
    }

    /// Get current ledger header
    pub fn current_header(&self) -> LedgerHeader {
        self.current_header.read().clone()
    }

    /// Close a ledger with the given transaction set
    pub fn close_ledger(
        &self,
        ledger_seq: u32,
        tx_set: &TransactionSet,
        stellar_value: &StellarValue,
    ) -> Result<LedgerCloseResult, LedgerError> {
        let mut header = self.current_header.write();

        // Verify we're closing the right ledger
        if ledger_seq != header.ledger_seq + 1 {
            return Err(LedgerError::InvalidSequence {
                expected: header.ledger_seq + 1,
                got: ledger_seq,
            });
        }

        tracing::info!(ledger = ledger_seq, "Closing ledger");

        // Create ledger delta to track changes
        let mut delta = LedgerDelta::new(ledger_seq);

        // Apply upgrades first
        self.apply_upgrades(&mut delta, &stellar_value.upgrades)?;

        // Apply all transactions
        let results = self.apply_transactions(&mut delta, tx_set)?;

        // Update bucket list with changes
        self.update_bucket_list(&delta)?;

        // Compute new state hash
        let bucket_list_hash = self.bucket_list.read().hash();

        // Update header
        let new_header = LedgerHeader {
            ledger_version: self.protocol_version,
            previous_ledger_hash: header.hash()?,
            scp_value: stellar_value.clone(),
            tx_set_result_hash: compute_tx_set_result_hash(&results),
            bucket_list_hash: bucket_list_hash.into(),
            ledger_seq,
            total_coins: header.total_coins, // Updated by inflation/fees
            fee_pool: header.fee_pool + delta.fee_changes(),
            inflation_seq: header.inflation_seq,
            id_pool: header.id_pool + delta.id_allocations(),
            base_fee: header.base_fee,
            base_reserve: header.base_reserve,
            max_tx_set_size: header.max_tx_set_size,
            skip_list: compute_skip_list(&header),
            ext: LedgerHeaderExt::V0,
        };

        // Store in database
        self.store_ledger(&new_header, &delta)?;

        *header = new_header.clone();

        tracing::info!(
            ledger = ledger_seq,
            hash = %hex::encode(new_header.hash()?.as_bytes()),
            "Ledger closed"
        );

        Ok(LedgerCloseResult {
            header: new_header,
            tx_results: results,
            delta,
        })
    }

    fn apply_transactions(
        &self,
        delta: &mut LedgerDelta,
        tx_set: &TransactionSet,
    ) -> Result<Vec<TransactionResult>, LedgerError> {
        let mut results = Vec::new();

        for tx in &tx_set.txs {
            let result = self.apply_transaction(delta, tx)?;
            results.push(result);
        }

        Ok(results)
    }

    fn apply_transaction(
        &self,
        delta: &mut LedgerDelta,
        tx: &TransactionEnvelope,
    ) -> Result<TransactionResult, LedgerError> {
        // Delegate to transaction processor
        // This handles both classic and Soroban transactions
        let processor = TransactionProcessor::new(
            delta,
            &self.network_passphrase,
            self.protocol_version,
        );

        processor.apply(tx)
    }

    fn apply_upgrades(
        &self,
        delta: &mut LedgerDelta,
        upgrades: &[LedgerUpgrade],
    ) -> Result<(), LedgerError> {
        for upgrade in upgrades {
            match upgrade {
                LedgerUpgrade::Version(v) => {
                    self.protocol_version = *v;
                }
                LedgerUpgrade::BaseFee(fee) => {
                    // Update base fee
                }
                LedgerUpgrade::MaxTxSetSize(size) => {
                    // Update max tx set size
                }
                LedgerUpgrade::BaseReserve(reserve) => {
                    // Update base reserve
                }
                _ => {
                    // Handle other upgrades
                }
            }
        }
        Ok(())
    }

    fn update_bucket_list(&self, delta: &LedgerDelta) -> Result<(), LedgerError> {
        let entries: Vec<BucketEntry> = delta.changes()
            .map(|change| match change {
                LedgerEntryChange::Created(entry) => BucketEntry::LiveEntry(entry.clone()),
                LedgerEntryChange::Updated(entry) => BucketEntry::LiveEntry(entry.clone()),
                LedgerEntryChange::Deleted(key) => BucketEntry::DeadEntry(key.clone()),
            })
            .collect();

        let mut bucket_list = self.bucket_list.write();
        tokio::runtime::Handle::current().block_on(async {
            bucket_list.add_batch(
                delta.ledger_seq(),
                entries,
                &self.bucket_manager,
            ).await
        })?;

        Ok(())
    }

    /// Load a ledger entry
    pub fn load_entry(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>, LedgerError> {
        // Try bucket list first (includes Soroban state)
        if let Some(entry) = self.bucket_list.read().get(key)? {
            return Ok(Some(entry));
        }

        // Fall back to database for classic entries
        self.database.load_entry(key)
    }

    /// Load an account
    pub fn load_account(&self, account_id: &AccountId) -> Result<Option<AccountEntry>, LedgerError> {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: account_id.clone(),
        });

        match self.load_entry(&key)? {
            Some(LedgerEntry { data: LedgerEntryData::Account(account), .. }) => Ok(Some(account)),
            _ => Ok(None),
        }
    }

    /// Get a snapshot for reading
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            header: self.current_header.read().clone(),
            bucket_list: self.bucket_list.read().snapshot(),
        }
    }
}
```

#### LedgerDelta

```rust
/// Tracks changes during ledger close
pub struct LedgerDelta {
    ledger_seq: u32,
    /// Entry changes
    changes: Vec<LedgerEntryChange>,
    /// Fee collected
    fee_collected: i64,
    /// IDs allocated
    ids_allocated: u64,
}

#[derive(Clone)]
pub enum LedgerEntryChange {
    Created(LedgerEntry),
    Updated(LedgerEntry),
    Deleted(LedgerKey),
}

impl LedgerDelta {
    pub fn new(ledger_seq: u32) -> Self {
        Self {
            ledger_seq,
            changes: Vec::new(),
            fee_collected: 0,
            ids_allocated: 0,
        }
    }

    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    pub fn record_create(&mut self, entry: LedgerEntry) {
        self.changes.push(LedgerEntryChange::Created(entry));
    }

    pub fn record_update(&mut self, entry: LedgerEntry) {
        self.changes.push(LedgerEntryChange::Updated(entry));
    }

    pub fn record_delete(&mut self, key: LedgerKey) {
        self.changes.push(LedgerEntryChange::Deleted(key));
    }

    pub fn add_fee(&mut self, fee: i64) {
        self.fee_collected += fee;
    }

    pub fn allocate_id(&mut self) -> u64 {
        self.ids_allocated += 1;
        self.ids_allocated
    }

    pub fn changes(&self) -> impl Iterator<Item = &LedgerEntryChange> {
        self.changes.iter()
    }

    pub fn fee_changes(&self) -> i64 {
        self.fee_collected
    }

    pub fn id_allocations(&self) -> u64 {
        self.ids_allocated
    }
}
```

#### LedgerTxn (Ledger Transaction)

```rust
/// Transaction context for ledger operations
pub struct LedgerTxn<'a> {
    delta: &'a mut LedgerDelta,
    snapshot: LedgerSnapshot,
    /// Local modifications (not yet committed)
    local_changes: HashMap<LedgerKey, Option<LedgerEntry>>,
}

impl<'a> LedgerTxn<'a> {
    pub fn new(delta: &'a mut LedgerDelta, snapshot: LedgerSnapshot) -> Self {
        Self {
            delta,
            snapshot,
            local_changes: HashMap::new(),
        }
    }

    /// Load an entry (checks local changes first)
    pub fn load(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>, LedgerError> {
        // Check local changes first
        if let Some(entry) = self.local_changes.get(key) {
            return Ok(entry.clone());
        }

        // Fall back to snapshot
        self.snapshot.load(key)
    }

    /// Load entry for modification
    pub fn load_mut(&mut self, key: &LedgerKey) -> Result<Option<&mut LedgerEntry>, LedgerError> {
        if !self.local_changes.contains_key(key) {
            let entry = self.snapshot.load(key)?;
            self.local_changes.insert(key.clone(), entry);
        }

        Ok(self.local_changes.get_mut(key).and_then(|e| e.as_mut()))
    }

    /// Create a new entry
    pub fn create(&mut self, entry: LedgerEntry) -> Result<(), LedgerError> {
        let key = entry.to_key();
        if self.load(&key)?.is_some() {
            return Err(LedgerError::EntryExists(key));
        }
        self.local_changes.insert(key, Some(entry));
        Ok(())
    }

    /// Delete an entry
    pub fn delete(&mut self, key: &LedgerKey) -> Result<(), LedgerError> {
        if self.load(key)?.is_none() {
            return Err(LedgerError::EntryNotFound(key.clone()));
        }
        self.local_changes.insert(key.clone(), None);
        Ok(())
    }

    /// Commit changes to delta
    pub fn commit(self) {
        for (key, entry) in self.local_changes {
            match entry {
                Some(e) => {
                    // Check if this was a create or update
                    if self.snapshot.load(&key).ok().flatten().is_some() {
                        self.delta.record_update(e);
                    } else {
                        self.delta.record_create(e);
                    }
                }
                None => {
                    self.delta.record_delete(key);
                }
            }
        }
    }
}
```

#### LedgerSnapshot

```rust
/// Point-in-time read-only view of ledger state
pub struct LedgerSnapshot {
    pub header: LedgerHeader,
    pub bucket_list: BucketListSnapshot,
}

impl LedgerSnapshot {
    pub fn load(&self, key: &LedgerKey) -> Result<Option<LedgerEntry>, LedgerError> {
        self.bucket_list.get(key).map_err(|e| e.into())
    }

    pub fn ledger_seq(&self) -> u32 {
        self.header.ledger_seq
    }

    pub fn protocol_version(&self) -> u32 {
        self.header.ledger_version
    }
}
```

### 3.4 Ledger Close Result

```rust
pub struct LedgerCloseResult {
    pub header: LedgerHeader,
    pub tx_results: Vec<TransactionResult>,
    pub delta: LedgerDelta,
}

impl LedgerCloseResult {
    /// Get the ledger hash
    pub fn ledger_hash(&self) -> Result<Hash256, LedgerError> {
        self.header.hash()
    }

    /// Get applied transaction count
    pub fn tx_count(&self) -> usize {
        self.tx_results.len()
    }

    /// Get successful transaction count
    pub fn successful_tx_count(&self) -> usize {
        self.tx_results.iter()
            .filter(|r| r.result.is_success())
            .count()
    }
}
```

### 3.5 Skip List

```rust
/// Compute the skip list for a new ledger header
pub fn compute_skip_list(prev_header: &LedgerHeader) -> [Hash256; 4] {
    let prev_seq = prev_header.ledger_seq;
    let prev_hash = prev_header.hash().unwrap_or(Hash256::ZERO);

    let mut skip_list = prev_header.skip_list.clone();

    // Update skip list positions
    // Position 0: every ledger
    // Position 1: every 2 ledgers
    // Position 2: every 8 ledgers
    // Position 3: every 64 ledgers

    if prev_seq % 64 == 0 {
        skip_list[3] = skip_list[2];
    }
    if prev_seq % 8 == 0 {
        skip_list[2] = skip_list[1];
    }
    if prev_seq % 2 == 0 {
        skip_list[1] = skip_list[0];
    }
    skip_list[0] = prev_hash;

    skip_list
}
```

## 4. Error Types

```rust
#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("Invalid sequence: expected {expected}, got {got}")]
    InvalidSequence { expected: u32, got: u32 },

    #[error("Entry exists: {0:?}")]
    EntryExists(LedgerKey),

    #[error("Entry not found: {0:?}")]
    EntryNotFound(LedgerKey),

    #[error("Bucket error: {0}")]
    Bucket(#[from] BucketError),

    #[error("Database error: {0}")]
    Database(#[from] DbError),

    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::Error),

    #[error("Transaction error: {0}")]
    Transaction(#[from] TransactionError),

    #[error("Invalid header: {0}")]
    InvalidHeader(String),
}
```

## 5. Tests to Port from stellar-core

From `src/ledger/test/`:
- Ledger close sequence
- State hash computation
- Entry CRUD operations
- Snapshot isolation
- Skip list computation
- Upgrade handling

## 6. Performance Considerations

1. **State caching**: Keep frequently accessed entries in memory
2. **Batch operations**: Group database writes
3. **Parallel validation**: Validate transactions in parallel where possible
4. **Snapshot isolation**: Use efficient copy-on-write for snapshots
