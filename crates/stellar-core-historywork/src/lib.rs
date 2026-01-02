//! History work items for rs-stellar-core.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use flate2::{write::GzEncoder, Compression};
use tokio::sync::Mutex;

use stellar_core_common::Hash256;
use stellar_core_history::{
    archive::HistoryArchive,
    archive_state::HistoryArchiveState,
    paths::{bucket_path, checkpoint_path},
    verify,
    CheckpointData,
};
use stellar_core_ledger::TransactionSetVariant;
use stellar_core_work::{Work, WorkContext, WorkId, WorkOutcome, WorkScheduler};
use stellar_xdr::curr::{
    LedgerHeaderHistoryEntry, ScpHistoryEntry, TransactionHistoryEntry, TransactionHistoryEntryExt,
    TransactionHistoryResultEntry, WriteXdr,
};

/// Shared state between history work items.
#[derive(Debug, Default)]
pub struct HistoryWorkState {
    pub has: Option<HistoryArchiveState>,
    pub buckets: HashMap<Hash256, Vec<u8>>,
    pub headers: Vec<LedgerHeaderHistoryEntry>,
    pub transactions: Vec<TransactionHistoryEntry>,
    pub tx_results: Vec<TransactionHistoryResultEntry>,
    pub scp_history: Vec<ScpHistoryEntry>,
    pub progress: HistoryWorkProgress,
}

pub type SharedHistoryState = Arc<Mutex<HistoryWorkState>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryWorkStage {
    FetchHas,
    DownloadBuckets,
    DownloadHeaders,
    DownloadTransactions,
    DownloadResults,
    DownloadScp,
    PublishHas,
    PublishBuckets,
    PublishHeaders,
    PublishTransactions,
    PublishResults,
    PublishScp,
}

#[derive(Debug, Clone)]
pub struct HistoryWorkProgress {
    pub stage: Option<HistoryWorkStage>,
    pub message: String,
}

impl Default for HistoryWorkProgress {
    fn default() -> Self {
        Self {
            stage: None,
            message: String::new(),
        }
    }
}

async fn set_progress(state: &SharedHistoryState, stage: HistoryWorkStage, message: &str) {
    let mut guard = state.lock().await;
    guard.progress.stage = Some(stage);
    guard.progress.message = message.to_string();
}

/// Work to fetch the History Archive State (HAS).
pub struct GetHistoryArchiveStateWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl GetHistoryArchiveStateWork {
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for GetHistoryArchiveStateWork {
    fn name(&self) -> &str {
        "get-history-archive-state"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::FetchHas, "fetching HAS").await;
        match self.archive.get_checkpoint_has(self.checkpoint).await {
            Ok(has) => {
                let mut guard = self.state.lock().await;
                guard.has = Some(has);
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to fetch HAS: {}", err)),
        }
    }
}

/// Work to download and verify buckets referenced in HAS.
pub struct DownloadBucketsWork {
    archive: Arc<HistoryArchive>,
    state: SharedHistoryState,
}

impl DownloadBucketsWork {
    pub fn new(archive: Arc<HistoryArchive>, state: SharedHistoryState) -> Self {
        Self { archive, state }
    }
}

#[async_trait]
impl Work for DownloadBucketsWork {
    fn name(&self) -> &str {
        "download-buckets"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        use futures::stream::{self, StreamExt};

        set_progress(&self.state, HistoryWorkStage::DownloadBuckets, "downloading buckets").await;
        let has = {
            let guard = self.state.lock().await;
            guard.has.clone()
        };

        let Some(has) = has else {
            return WorkOutcome::Failed("missing HAS".to_string());
        };

        let hashes = has.unique_bucket_hashes();
        let total = hashes.len();
        let archive = self.archive.clone();

        // Download buckets in parallel (16 concurrent downloads, matching C++ MAX_CONCURRENT_SUBPROCESSES)
        let results: Vec<Result<(Hash256, Vec<u8>), String>> = stream::iter(hashes)
            .map(|hash| {
                let archive = archive.clone();
                async move {
                    match archive.get_bucket(&hash).await {
                        Ok(data) => {
                            if let Err(err) = verify::verify_bucket_hash(&data, &hash) {
                                Err(format!("bucket {} hash mismatch: {}", hash, err))
                            } else {
                                Ok((hash, data))
                            }
                        }
                        Err(err) => Err(format!("failed to download bucket {}: {}", hash, err)),
                    }
                }
            })
            .buffer_unordered(16)
            .collect()
            .await;

        // Check for failures and collect successful downloads
        let mut buckets = HashMap::new();
        for result in results {
            match result {
                Ok((hash, data)) => {
                    buckets.insert(hash, data);
                }
                Err(err) => {
                    return WorkOutcome::Failed(err);
                }
            }
        }

        tracing::info!("Downloaded {} buckets in parallel", total);

        let mut guard = self.state.lock().await;
        guard.buckets = buckets;
        WorkOutcome::Success
    }
}

/// Work to download ledger headers for a checkpoint.
pub struct DownloadLedgerHeadersWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl DownloadLedgerHeadersWork {
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for DownloadLedgerHeadersWork {
    fn name(&self) -> &str {
        "download-ledger-headers"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::DownloadHeaders, "downloading headers").await;
        match self.archive.get_ledger_headers(self.checkpoint).await {
            Ok(headers) => {
                let header_chain: Vec<_> = headers.iter().map(|entry| entry.header.clone()).collect();
                if let Err(err) = verify::verify_header_chain(&header_chain) {
                    return WorkOutcome::Failed(format!("header chain verification failed: {}", err));
                }
                let mut guard = self.state.lock().await;
                guard.headers = headers;
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to download headers: {}", err)),
        }
    }
}

/// Work to download transaction sets for a checkpoint.
pub struct DownloadTransactionsWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl DownloadTransactionsWork {
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for DownloadTransactionsWork {
    fn name(&self) -> &str {
        "download-transactions"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::DownloadTransactions, "downloading transactions").await;
        match self.archive.get_transactions(self.checkpoint).await {
            Ok(entries) => {
                let headers = {
                    let guard = self.state.lock().await;
                    guard.headers.clone()
                };
                for entry in &entries {
                    if let Some(header) = headers.iter().find(|h| h.header.ledger_seq == entry.ledger_seq) {
                        let tx_set = match &entry.ext {
                            TransactionHistoryEntryExt::V0 => {
                                TransactionSetVariant::Classic(entry.tx_set.clone())
                            }
                            TransactionHistoryEntryExt::V1(set) => {
                                TransactionSetVariant::Generalized(set.clone())
                            }
                        };
                        if let Err(err) = verify::verify_tx_set(&header.header, &tx_set) {
                            return WorkOutcome::Failed(format!("tx set hash mismatch: {}", err));
                        }
                    }
                }
                let mut guard = self.state.lock().await;
                guard.transactions = entries;
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to download transactions: {}", err)),
        }
    }
}

/// Work to download transaction results for a checkpoint.
pub struct DownloadTxResultsWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl DownloadTxResultsWork {
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for DownloadTxResultsWork {
    fn name(&self) -> &str {
        "download-tx-results"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        let headers = {
            let guard = self.state.lock().await;
            guard.headers.clone()
        };

        set_progress(&self.state, HistoryWorkStage::DownloadResults, "downloading transaction results").await;
        match self.archive.get_results(self.checkpoint).await {
            Ok(results) => {
                for entry in &results {
                    if let Some(header) = headers.iter().find(|h| h.header.ledger_seq == entry.ledger_seq) {
                        if let Ok(xdr) = entry.tx_result_set.to_xdr(stellar_xdr::curr::Limits::none()) {
                            if let Err(err) = verify::verify_tx_result_set(&header.header, &xdr) {
                                return WorkOutcome::Failed(format!("tx result set hash mismatch: {}", err));
                            }
                        }
                    }
                }
                let mut guard = self.state.lock().await;
                guard.tx_results = results;
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to download tx results: {}", err)),
        }
    }
}

/// Work to download SCP history for a checkpoint.
pub struct DownloadScpHistoryWork {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl DownloadScpHistoryWork {
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for DownloadScpHistoryWork {
    fn name(&self) -> &str {
        "download-scp-history"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::DownloadScp, "downloading SCP history").await;
        match self.archive.get_scp_history(self.checkpoint).await {
            Ok(entries) => {
                let mut guard = self.state.lock().await;
                guard.scp_history = entries;
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to download SCP history: {}", err)),
        }
    }
}

/// Archive writer for publish operations.
#[async_trait]
pub trait ArchiveWriter: Send + Sync {
    async fn put_bytes(&self, path: &str, data: &[u8]) -> Result<()>;
}

/// Local filesystem archive writer (for tests/local publish).
pub struct LocalArchiveWriter {
    base_dir: PathBuf,
}

impl LocalArchiveWriter {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    fn full_path(&self, path: &str) -> PathBuf {
        self.base_dir.join(path)
    }
}

#[async_trait]
impl ArchiveWriter for LocalArchiveWriter {
    async fn put_bytes(&self, path: &str, data: &[u8]) -> Result<()> {
        let full_path = self.full_path(path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(full_path, data)?;
        Ok(())
    }
}

fn gzip_bytes(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    use std::io::Write;
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn serialize_entries<T: WriteXdr>(entries: &[T]) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    for entry in entries {
        let xdr = entry.to_xdr(stellar_xdr::curr::Limits::none())?;
        data.extend_from_slice(&xdr);
    }
    Ok(data)
}

/// Work to publish the History Archive State (HAS).
pub struct PublishHistoryArchiveStateWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishHistoryArchiveStateWork {
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for PublishHistoryArchiveStateWork {
    fn name(&self) -> &str {
        "publish-has"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishHas, "publishing HAS").await;
        let has = {
            let guard = self.state.lock().await;
            guard.has.clone()
        };
        let Some(has) = has else {
            return WorkOutcome::Failed("HAS not available".to_string());
        };

        match has.to_json() {
            Ok(json) => {
                let path = checkpoint_path("history", self.checkpoint, "json");
                if let Err(err) = self.writer.put_bytes(&path, json.as_bytes()).await {
                    return WorkOutcome::Failed(format!("failed to publish HAS: {}", err));
                }
                WorkOutcome::Success
            }
            Err(err) => WorkOutcome::Failed(format!("failed to serialize HAS: {}", err)),
        }
    }
}

/// Work to publish bucket files from downloaded state.
pub struct PublishBucketsWork {
    writer: Arc<dyn ArchiveWriter>,
    state: SharedHistoryState,
}

impl PublishBucketsWork {
    pub fn new(writer: Arc<dyn ArchiveWriter>, state: SharedHistoryState) -> Self {
        Self { writer, state }
    }
}

/// Work to publish ledger headers.
pub struct PublishLedgerHeadersWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishLedgerHeadersWork {
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for PublishLedgerHeadersWork {
    fn name(&self) -> &str {
        "publish-ledger-headers"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishHeaders, "publishing headers").await;
        let headers = {
            let guard = self.state.lock().await;
            guard.headers.clone()
        };

        let data = match serialize_entries(&headers) {
            Ok(data) => data,
            Err(err) => return WorkOutcome::Failed(format!("failed to serialize headers: {}", err)),
        };
        let gz = match gzip_bytes(&data) {
            Ok(gz) => gz,
            Err(err) => return WorkOutcome::Failed(format!("failed to gzip headers: {}", err)),
        };

        let path = checkpoint_path("ledger", self.checkpoint, "xdr.gz");
        if let Err(err) = self.writer.put_bytes(&path, &gz).await {
            return WorkOutcome::Failed(format!("failed to publish headers: {}", err));
        }

        WorkOutcome::Success
    }
}

/// Work to publish transaction history entries.
pub struct PublishTransactionsWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishTransactionsWork {
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for PublishTransactionsWork {
    fn name(&self) -> &str {
        "publish-transactions"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(
            &self.state,
            HistoryWorkStage::PublishTransactions,
            "publishing transactions",
        )
        .await;
        let transactions = {
            let guard = self.state.lock().await;
            guard.transactions.clone()
        };

        let data = match serialize_entries(&transactions) {
            Ok(data) => data,
            Err(err) => {
                return WorkOutcome::Failed(format!(
                    "failed to serialize transactions: {}",
                    err
                ))
            }
        };
        let gz = match gzip_bytes(&data) {
            Ok(gz) => gz,
            Err(err) => {
                return WorkOutcome::Failed(format!("failed to gzip transactions: {}", err))
            }
        };

        let path = checkpoint_path("transactions", self.checkpoint, "xdr.gz");
        if let Err(err) = self.writer.put_bytes(&path, &gz).await {
            return WorkOutcome::Failed(format!("failed to publish transactions: {}", err));
        }

        WorkOutcome::Success
    }
}

/// Work to publish transaction results.
pub struct PublishResultsWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishResultsWork {
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

/// Work to publish SCP history entries.
pub struct PublishScpHistoryWork {
    writer: Arc<dyn ArchiveWriter>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl PublishScpHistoryWork {
    pub fn new(writer: Arc<dyn ArchiveWriter>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            writer,
            checkpoint,
            state,
        }
    }
}

#[async_trait]
impl Work for PublishResultsWork {
    fn name(&self) -> &str {
        "publish-results"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishResults, "publishing results").await;
        let results = {
            let guard = self.state.lock().await;
            guard.tx_results.clone()
        };

        let data = match serialize_entries(&results) {
            Ok(data) => data,
            Err(err) => return WorkOutcome::Failed(format!("failed to serialize results: {}", err)),
        };
        let gz = match gzip_bytes(&data) {
            Ok(gz) => gz,
            Err(err) => return WorkOutcome::Failed(format!("failed to gzip results: {}", err)),
        };

        let path = checkpoint_path("results", self.checkpoint, "xdr.gz");
        if let Err(err) = self.writer.put_bytes(&path, &gz).await {
            return WorkOutcome::Failed(format!("failed to publish results: {}", err));
        }

        WorkOutcome::Success
    }
}

#[async_trait]
impl Work for PublishScpHistoryWork {
    fn name(&self) -> &str {
        "publish-scp-history"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishScp, "publishing SCP history").await;
        let entries = {
            let guard = self.state.lock().await;
            guard.scp_history.clone()
        };

        if entries.is_empty() {
            return WorkOutcome::Failed("SCP history not available".to_string());
        }

        let data = match serialize_entries(&entries) {
            Ok(data) => data,
            Err(err) => return WorkOutcome::Failed(format!("failed to serialize SCP history: {}", err)),
        };
        let gz = match gzip_bytes(&data) {
            Ok(gz) => gz,
            Err(err) => return WorkOutcome::Failed(format!("failed to gzip SCP history: {}", err)),
        };

        let path = checkpoint_path("scp", self.checkpoint, "xdr.gz");
        if let Err(err) = self.writer.put_bytes(&path, &gz).await {
            return WorkOutcome::Failed(format!("failed to publish SCP history: {}", err));
        }

        WorkOutcome::Success
    }
}

#[async_trait]
impl Work for PublishBucketsWork {
    fn name(&self) -> &str {
        "publish-buckets"
    }

    async fn run(&mut self, _ctx: WorkContext) -> WorkOutcome {
        set_progress(&self.state, HistoryWorkStage::PublishBuckets, "publishing buckets").await;
        let buckets = {
            let guard = self.state.lock().await;
            guard.buckets.clone()
        };

        if buckets.is_empty() {
            return WorkOutcome::Failed("buckets not available".to_string());
        }

        for (hash, data) in buckets {
            match gzip_bytes(&data) {
                Ok(gz) => {
                    let path = bucket_path(&hash);
                    if let Err(err) = self.writer.put_bytes(&path, &gz).await {
                        return WorkOutcome::Failed(format!("failed to publish bucket: {}", err));
                    }
                }
                Err(err) => return WorkOutcome::Failed(format!("failed to gzip bucket: {}", err)),
            }
        }

        WorkOutcome::Success
    }
}

/// IDs for registered history work items.
#[derive(Debug, Clone, Copy)]
pub struct HistoryWorkIds {
    pub has: WorkId,
    pub buckets: WorkId,
    pub headers: WorkId,
    pub transactions: WorkId,
    pub tx_results: WorkId,
    pub scp_history: WorkId,
}

#[derive(Debug, Clone, Copy)]
pub struct PublishWorkIds {
    pub has: WorkId,
    pub buckets: WorkId,
    pub headers: WorkId,
    pub transactions: WorkId,
    pub results: WorkId,
    pub scp_history: WorkId,
}

/// Builder for registering history work items with the scheduler.
pub struct HistoryWorkBuilder {
    archive: Arc<HistoryArchive>,
    checkpoint: u32,
    state: SharedHistoryState,
}

impl HistoryWorkBuilder {
    pub fn new(archive: Arc<HistoryArchive>, checkpoint: u32, state: SharedHistoryState) -> Self {
        Self {
            archive,
            checkpoint,
            state,
        }
    }

    pub fn register(&self, scheduler: &mut WorkScheduler) -> HistoryWorkIds {
        let has_id = scheduler.add_work(
            Box::new(GetHistoryArchiveStateWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![],
            3,
        );

        let buckets_id = scheduler.add_work(
            Box::new(DownloadBucketsWork::new(
                Arc::clone(&self.archive),
                Arc::clone(&self.state),
            )),
            vec![has_id],
            3,
        );

        let headers_id = scheduler.add_work(
            Box::new(DownloadLedgerHeadersWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![has_id],
            3,
        );

        let tx_id = scheduler.add_work(
            Box::new(DownloadTransactionsWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![headers_id],
            3,
        );

        let tx_results_id = scheduler.add_work(
            Box::new(DownloadTxResultsWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![headers_id, tx_id],
            3,
        );

        let scp_id = scheduler.add_work(
            Box::new(DownloadScpHistoryWork::new(
                Arc::clone(&self.archive),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![headers_id],
            3,
        );

        HistoryWorkIds {
            has: has_id,
            buckets: buckets_id,
            headers: headers_id,
            transactions: tx_id,
            tx_results: tx_results_id,
            scp_history: scp_id,
        }
    }

    pub fn register_publish(
        &self,
        scheduler: &mut WorkScheduler,
        writer: Arc<dyn ArchiveWriter>,
        deps: HistoryWorkIds,
    ) -> PublishWorkIds {
        let has_id = scheduler.add_work(
            Box::new(PublishHistoryArchiveStateWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.has],
            2,
        );

        let buckets_id = scheduler.add_work(
            Box::new(PublishBucketsWork::new(
                Arc::clone(&writer),
                Arc::clone(&self.state),
            )),
            vec![deps.buckets],
            2,
        );

        let headers_id = scheduler.add_work(
            Box::new(PublishLedgerHeadersWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.headers],
            2,
        );

        let transactions_id = scheduler.add_work(
            Box::new(PublishTransactionsWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.transactions],
            2,
        );

        let results_id = scheduler.add_work(
            Box::new(PublishResultsWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.tx_results],
            2,
        );

        let scp_id = scheduler.add_work(
            Box::new(PublishScpHistoryWork::new(
                Arc::clone(&writer),
                self.checkpoint,
                Arc::clone(&self.state),
            )),
            vec![deps.scp_history],
            2,
        );

        PublishWorkIds {
            has: has_id,
            buckets: buckets_id,
            headers: headers_id,
            transactions: transactions_id,
            results: results_id,
            scp_history: scp_id,
        }
    }
}

/// Helper for retrieving the HAS from shared state.
pub async fn get_has(state: &SharedHistoryState) -> Result<HistoryArchiveState> {
    let guard = state.lock().await;
    guard
        .has
        .clone()
        .ok_or_else(|| anyhow::anyhow!("HAS not available"))
}

/// Helper for retrieving buckets from shared state.
pub async fn get_buckets(state: &SharedHistoryState) -> Result<HashMap<Hash256, Vec<u8>>> {
    let guard = state.lock().await;
    if guard.buckets.is_empty() {
        anyhow::bail!("buckets not available");
    }
    Ok(guard.buckets.clone())
}

pub async fn get_headers(state: &SharedHistoryState) -> Result<Vec<LedgerHeaderHistoryEntry>> {
    let guard = state.lock().await;
    if guard.headers.is_empty() {
        anyhow::bail!("headers not available");
    }
    Ok(guard.headers.clone())
}

pub async fn get_transactions(state: &SharedHistoryState) -> Result<Vec<TransactionHistoryEntry>> {
    let guard = state.lock().await;
    if guard.transactions.is_empty() {
        anyhow::bail!("transactions not available");
    }
    Ok(guard.transactions.clone())
}

pub async fn get_tx_results(state: &SharedHistoryState) -> Result<Vec<TransactionHistoryResultEntry>> {
    let guard = state.lock().await;
    if guard.tx_results.is_empty() {
        anyhow::bail!("tx results not available");
    }
    Ok(guard.tx_results.clone())
}

pub async fn get_scp_history(state: &SharedHistoryState) -> Result<Vec<ScpHistoryEntry>> {
    let guard = state.lock().await;
    if guard.scp_history.is_empty() {
        anyhow::bail!("scp history not available");
    }
    Ok(guard.scp_history.clone())
}

pub async fn get_progress(state: &SharedHistoryState) -> HistoryWorkProgress {
    let guard = state.lock().await;
    guard.progress.clone()
}

/// Build checkpoint data for catchup from the shared history work state.
pub async fn build_checkpoint_data(state: &SharedHistoryState) -> Result<CheckpointData> {
    let guard = state.lock().await;
    let has = guard
        .has
        .clone()
        .ok_or_else(|| anyhow!("missing History Archive State"))?;

    Ok(CheckpointData {
        has,
        buckets: guard.buckets.clone(),
        headers: guard.headers.clone(),
        transactions: guard.transactions.clone(),
        tx_results: guard.tx_results.clone(),
        scp_history: guard.scp_history.clone(),
    })
}
