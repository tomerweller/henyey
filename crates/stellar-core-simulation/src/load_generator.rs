//! Load generator for simulation testing.
//!
//! This module provides utilities for generating synthetic transaction load,
//! primarily for use in simulation and performance testing scenarios. It matches
//! the C++ `LoadGenerator` class from `stellar-core/src/simulation/LoadGenerator.cpp`.
//!
//! # Overview
//!
//! The [`LoadGenerator`] creates and submits transactions at a configurable rate,
//! supporting various modes of operation. It builds on top of [`TxGenerator`] for
//! transaction creation and manages account pools to avoid sequence number conflicts.
//!
//! # Example
//!
//! ```ignore
//! use stellar_core_simulation::load_generator::{LoadGenerator, GeneratedLoadConfig, LoadGenMode};
//! use stellar_core_simulation::tx_generator::TxGeneratorConfig;
//! use stellar_core_crypto::SecretKey;
//!
//! // Create load generator with root account
//! let root_secret = SecretKey::generate();
//! let tx_config = TxGeneratorConfig::testnet();
//! let mut generator = LoadGenerator::new(root_secret, tx_config);
//!
//! // Configure and generate load
//! let config = GeneratedLoadConfig::new(LoadGenMode::Pay)
//!     .with_accounts(100)
//!     .with_txs(1000)
//!     .with_tx_rate(50); // 50 TPS
//!
//! // Start load generation
//! generator.start(&config);
//!
//! // Generate transactions for one step (100ms)
//! let txs = generator.generate_step(&config);
//! ```

use rand::Rng;
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};
use stellar_core_crypto::SecretKey;
use stellar_xdr::curr::TransactionEnvelope;

use crate::tx_generator::{TxGenerator, TxGeneratorConfig};

// =============================================================================
// Constants
// =============================================================================

/// Step interval for load generation in milliseconds.
/// Each step generates `tx_rate * STEP_MSECS / 1000` transactions.
pub const STEP_MSECS: u64 = 100;

/// Minimum multiplier for available accounts vs concurrent transactions.
/// Ensures enough accounts to avoid sequence number collisions.
pub const MIN_UNIQUE_ACCOUNT_MULTIPLIER: u32 = 3;

/// Maximum retries for transaction submission.
pub const TX_SUBMIT_MAX_TRIES: u32 = 10;

// =============================================================================
// LoadGenMode
// =============================================================================

/// Mode of operation for load generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoadGenMode {
    /// Simple payment transactions between accounts.
    Pay,
    /// Deploy random Wasm blobs (Soroban upload).
    SorobanUpload,
    /// Setup contracts for invocation (deploy wasm + create instances).
    SorobanInvokeSetup,
    /// Invoke resource-intensive Soroban transactions.
    SorobanInvoke,
    /// Setup for network config upgrade.
    SorobanUpgradeSetup,
    /// Create upgrade entry.
    SorobanCreateUpgrade,
    /// Mixed classic and Soroban transactions.
    MixedClassicSoroban,
    /// Submit pre-generated transactions from XDR file.
    PayPregenerated,
}

impl LoadGenMode {
    /// Returns true if this mode requires Soroban support.
    pub fn is_soroban(&self) -> bool {
        matches!(
            self,
            LoadGenMode::SorobanUpload
                | LoadGenMode::SorobanInvokeSetup
                | LoadGenMode::SorobanInvoke
                | LoadGenMode::SorobanUpgradeSetup
                | LoadGenMode::SorobanCreateUpgrade
                | LoadGenMode::MixedClassicSoroban
        )
    }

    /// Returns the name of this mode.
    pub fn name(&self) -> &'static str {
        match self {
            LoadGenMode::Pay => "PAY",
            LoadGenMode::SorobanUpload => "SOROBAN_UPLOAD",
            LoadGenMode::SorobanInvokeSetup => "SOROBAN_INVOKE_SETUP",
            LoadGenMode::SorobanInvoke => "SOROBAN_INVOKE",
            LoadGenMode::SorobanUpgradeSetup => "SOROBAN_UPGRADE_SETUP",
            LoadGenMode::SorobanCreateUpgrade => "SOROBAN_CREATE_UPGRADE",
            LoadGenMode::MixedClassicSoroban => "MIXED_CLASSIC_SOROBAN",
            LoadGenMode::PayPregenerated => "PAY_PREGENERATED",
        }
    }
}

// =============================================================================
// GeneratedLoadConfig
// =============================================================================

/// Configuration for load generation.
#[derive(Debug, Clone)]
pub struct GeneratedLoadConfig {
    /// Mode of operation.
    pub mode: LoadGenMode,
    /// Number of accounts to use.
    pub n_accounts: u32,
    /// Number of transactions to generate.
    pub n_txs: u32,
    /// Target transactions per second.
    pub tx_rate: u32,
    /// Account ID offset.
    pub offset: u32,
    /// Interval between traffic spikes (None = no spikes).
    pub spike_interval: Option<Duration>,
    /// Number of additional txs per spike.
    pub spike_size: u32,
    /// Maximum fee rate for random fee generation (None = use base fee).
    pub max_fee_rate: Option<u32>,
    /// Skip transactions rejected due to low fees.
    pub skip_low_fee_txs: bool,
    /// Current ledger number for sequence number initialization.
    pub ledger_num: u32,
}

impl GeneratedLoadConfig {
    /// Creates a new configuration with the specified mode.
    pub fn new(mode: LoadGenMode) -> Self {
        Self {
            mode,
            n_accounts: 100,
            n_txs: 1000,
            tx_rate: 10,
            offset: 0,
            spike_interval: None,
            spike_size: 0,
            max_fee_rate: None,
            skip_low_fee_txs: false,
            ledger_num: 1,
        }
    }

    /// Sets the number of accounts.
    pub fn with_accounts(mut self, n: u32) -> Self {
        self.n_accounts = n;
        self
    }

    /// Sets the number of transactions.
    pub fn with_txs(mut self, n: u32) -> Self {
        self.n_txs = n;
        self
    }

    /// Sets the target transaction rate.
    pub fn with_tx_rate(mut self, rate: u32) -> Self {
        self.tx_rate = rate;
        self
    }

    /// Sets the account offset.
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }

    /// Sets the spike interval and size.
    pub fn with_spikes(mut self, interval: Duration, size: u32) -> Self {
        self.spike_interval = Some(interval);
        self.spike_size = size;
        self
    }

    /// Sets the maximum fee rate.
    pub fn with_max_fee_rate(mut self, rate: u32) -> Self {
        self.max_fee_rate = Some(rate);
        self
    }

    /// Sets the ledger number for sequence initialization.
    pub fn with_ledger_num(mut self, ledger: u32) -> Self {
        self.ledger_num = ledger;
        self
    }

    /// Enables skipping low-fee transactions.
    pub fn skip_low_fees(mut self) -> Self {
        self.skip_low_fee_txs = true;
        self
    }

    /// Calculates transactions per step based on rate and step duration.
    pub fn txs_per_step(&self) -> u32 {
        (self.tx_rate as u64 * STEP_MSECS / 1000).max(1) as u32
    }
}

impl Default for GeneratedLoadConfig {
    fn default() -> Self {
        Self::new(LoadGenMode::Pay)
    }
}

// =============================================================================
// LoadGenMetrics
// =============================================================================

/// Metrics for load generation.
#[derive(Debug, Clone, Default)]
pub struct LoadGenMetrics {
    /// Total transactions attempted.
    pub txs_attempted: u64,
    /// Total transactions submitted successfully.
    pub txs_submitted: u64,
    /// Transactions rejected due to bad sequence.
    pub txs_bad_seq: u64,
    /// Transactions rejected due to low fee.
    pub txs_low_fee: u64,
    /// Transactions skipped.
    pub txs_skipped: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Start time of current load run.
    pub start_time: Option<Instant>,
    /// Time of last progress log.
    pub last_log_time: Option<Instant>,
}

impl LoadGenMetrics {
    /// Creates new empty metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets all metrics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Marks the start of a load run.
    pub fn start(&mut self) {
        let now = Instant::now();
        self.start_time = Some(now);
        self.last_log_time = Some(now);
    }

    /// Returns the elapsed time since start.
    pub fn elapsed(&self) -> Duration {
        self.start_time
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Returns the submission rate (TPS).
    pub fn submission_rate(&self) -> f64 {
        let elapsed = self.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.txs_submitted as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Records a successful submission.
    pub fn record_submission(&mut self, bytes: u64) {
        self.txs_attempted += 1;
        self.txs_submitted += 1;
        self.bytes_sent += bytes;
    }

    /// Records a bad sequence rejection.
    pub fn record_bad_seq(&mut self) {
        self.txs_attempted += 1;
        self.txs_bad_seq += 1;
    }

    /// Records a low fee rejection.
    pub fn record_low_fee(&mut self, skipped: bool) {
        self.txs_attempted += 1;
        self.txs_low_fee += 1;
        if skipped {
            self.txs_skipped += 1;
        }
    }
}

// =============================================================================
// LoadGeneratorState
// =============================================================================

/// Internal state for load generation.
#[derive(Debug)]
struct LoadGeneratorState {
    /// Accounts available for transaction generation.
    accounts_available: VecDeque<u64>,
    /// Accounts currently in use (pending transactions).
    accounts_in_use: HashSet<u64>,
    /// Number of transactions submitted in this run.
    txs_submitted: u32,
    /// Whether a load run is currently active.
    running: bool,
    /// Last spike time.
    last_spike_time: Option<Instant>,
}

impl LoadGeneratorState {
    /// Creates new state with the given accounts.
    fn new(n_accounts: u32, offset: u32) -> Self {
        let accounts: VecDeque<u64> = (0..n_accounts)
            .map(|i| (i + offset) as u64)
            .collect();

        Self {
            accounts_available: accounts,
            accounts_in_use: HashSet::new(),
            txs_submitted: 0,
            running: false,
            last_spike_time: None,
        }
    }

    /// Returns true if accounts are available.
    #[allow(dead_code)]
    fn has_available_accounts(&self) -> bool {
        !self.accounts_available.is_empty()
    }

    /// Takes the next available account.
    fn take_account(&mut self) -> Option<u64> {
        if let Some(account) = self.accounts_available.pop_front() {
            self.accounts_in_use.insert(account);
            Some(account)
        } else {
            None
        }
    }

    /// Returns an account to the available pool.
    fn return_account(&mut self, account: u64) {
        if self.accounts_in_use.remove(&account) {
            self.accounts_available.push_back(account);
        }
    }

    /// Returns all in-use accounts to the available pool.
    fn return_all_accounts(&mut self) {
        for account in self.accounts_in_use.drain() {
            self.accounts_available.push_back(account);
        }
    }

    /// Resets the state for a new run.
    fn reset(&mut self, n_accounts: u32, offset: u32) {
        *self = Self::new(n_accounts, offset);
    }
}

// =============================================================================
// LoadGenerator
// =============================================================================

/// A load generator for simulation testing.
///
/// This generator creates and submits transactions at a configurable rate,
/// managing account pools to avoid sequence number conflicts.
pub struct LoadGenerator {
    /// Transaction generator.
    tx_gen: TxGenerator,
    /// Metrics.
    metrics: LoadGenMetrics,
    /// Internal state.
    state: LoadGeneratorState,
    /// Random number generator.
    rng: rand::rngs::ThreadRng,
}

impl LoadGenerator {
    /// Creates a new load generator with the given root secret.
    pub fn new(root_secret: SecretKey, tx_config: TxGeneratorConfig) -> Self {
        Self {
            tx_gen: TxGenerator::new(root_secret, tx_config),
            metrics: LoadGenMetrics::new(),
            state: LoadGeneratorState::new(0, 0),
            rng: rand::thread_rng(),
        }
    }

    /// Creates a generator with a randomly generated root account.
    pub fn with_random_root(tx_config: TxGeneratorConfig) -> Self {
        let root_secret = SecretKey::generate();
        Self::new(root_secret, tx_config)
    }

    /// Returns a reference to the transaction generator.
    pub fn tx_generator(&self) -> &TxGenerator {
        &self.tx_gen
    }

    /// Returns a mutable reference to the transaction generator.
    pub fn tx_generator_mut(&mut self) -> &mut TxGenerator {
        &mut self.tx_gen
    }

    /// Returns a reference to the metrics.
    pub fn metrics(&self) -> &LoadGenMetrics {
        &self.metrics
    }

    /// Returns true if a load run is currently active.
    pub fn is_running(&self) -> bool {
        self.state.running
    }

    /// Starts a new load generation run.
    ///
    /// This initializes the account pool and metrics for the run.
    pub fn start(&mut self, config: &GeneratedLoadConfig) {
        // Reset state
        self.state.reset(config.n_accounts, config.offset);
        self.metrics.reset();
        self.metrics.start();
        self.state.running = true;

        // Update tx generator fee rate if specified
        // (Would need to extend TxGeneratorConfig for this)
    }

    /// Stops the current load generation run.
    pub fn stop(&mut self) {
        self.state.running = false;
        self.state.return_all_accounts();
    }

    /// Generates transactions for one step.
    ///
    /// Returns a vector of generated transactions. The caller is responsible
    /// for submitting these to the network.
    ///
    /// # Arguments
    ///
    /// * `config` - The load configuration
    ///
    /// # Returns
    ///
    /// A vector of (source_account_id, transaction) pairs.
    pub fn generate_step(
        &mut self,
        config: &GeneratedLoadConfig,
    ) -> Vec<(u64, TransactionEnvelope)> {
        if !self.state.running {
            return Vec::new();
        }

        let remaining = config.n_txs.saturating_sub(self.state.txs_submitted);
        if remaining == 0 {
            self.state.running = false;
            return Vec::new();
        }

        // Calculate transactions for this step
        let mut txs_this_step = config.txs_per_step().min(remaining);

        // Add spike transactions if applicable
        if let Some(spike_interval) = config.spike_interval {
            let should_spike = self.state.last_spike_time
                .map(|t| t.elapsed() >= spike_interval)
                .unwrap_or(true);

            if should_spike && config.spike_size > 0 {
                txs_this_step = txs_this_step.saturating_add(config.spike_size);
                self.state.last_spike_time = Some(Instant::now());
            }
        }

        let mut transactions = Vec::with_capacity(txs_this_step as usize);

        for _ in 0..txs_this_step {
            // Get available account
            let source_id = match self.state.take_account() {
                Some(id) => id,
                None => break, // No more accounts available
            };

            // Generate transaction based on mode
            let tx = match config.mode {
                LoadGenMode::Pay => self.generate_payment_tx(config, source_id),
                LoadGenMode::SorobanUpload
                | LoadGenMode::SorobanInvokeSetup
                | LoadGenMode::SorobanInvoke
                | LoadGenMode::SorobanUpgradeSetup
                | LoadGenMode::SorobanCreateUpgrade
                | LoadGenMode::MixedClassicSoroban
                | LoadGenMode::PayPregenerated => {
                    // Soroban modes not yet implemented
                    // Return account and skip
                    self.state.return_account(source_id);
                    continue;
                }
            };

            if let Some((account_id, envelope)) = tx {
                transactions.push((account_id, envelope));
                self.state.txs_submitted += 1;
            } else {
                // Failed to generate, return account
                self.state.return_account(source_id);
            }
        }

        transactions
    }

    /// Generates a payment transaction.
    fn generate_payment_tx(
        &mut self,
        config: &GeneratedLoadConfig,
        source_id: u64,
    ) -> Option<(u64, TransactionEnvelope)> {
        // Select destination (different from source)
        // Note: destination selection is done inside payment_transaction
        let _dest_offset = self.rng.gen_range(1..config.n_accounts) as u64;

        // Generate payment from source to dest
        Some(self.tx_gen.payment_transaction(
            config.n_accounts,
            config.offset,
            config.ledger_num,
            source_id,
        ))
    }

    /// Records a successful transaction submission.
    pub fn record_submission(&mut self, source_id: u64, tx_bytes: u64) {
        self.metrics.record_submission(tx_bytes);
        self.state.return_account(source_id);
    }

    /// Records a failed transaction submission (bad sequence).
    pub fn record_bad_seq(&mut self, source_id: u64) {
        self.metrics.record_bad_seq();
        // Account will need sequence refresh before reuse
        self.state.return_account(source_id);
    }

    /// Records a failed transaction submission (low fee).
    pub fn record_low_fee(&mut self, source_id: u64, skip: bool) {
        self.metrics.record_low_fee(skip);
        self.state.return_account(source_id);
    }

    /// Returns the number of transactions remaining in this run.
    pub fn remaining_txs(&self, config: &GeneratedLoadConfig) -> u32 {
        config.n_txs.saturating_sub(self.state.txs_submitted)
    }

    /// Returns the number of available accounts.
    pub fn available_accounts(&self) -> usize {
        self.state.accounts_available.len()
    }

    /// Returns the number of accounts in use.
    pub fn accounts_in_use(&self) -> usize {
        self.state.accounts_in_use.len()
    }

    /// Logs progress information.
    pub fn log_progress(&mut self, config: &GeneratedLoadConfig) -> LoadProgress {
        let elapsed = self.metrics.elapsed();
        let remaining = self.remaining_txs(config);
        let rate = self.metrics.submission_rate();

        let eta = if rate > 0.0 {
            Duration::from_secs_f64(remaining as f64 / rate)
        } else {
            Duration::MAX
        };

        self.metrics.last_log_time = Some(Instant::now());

        LoadProgress {
            mode: config.mode,
            submitted: self.state.txs_submitted,
            remaining,
            elapsed,
            rate,
            eta,
        }
    }
}

// =============================================================================
// LoadProgress
// =============================================================================

/// Progress information for load generation.
#[derive(Debug, Clone)]
pub struct LoadProgress {
    /// Mode of operation.
    pub mode: LoadGenMode,
    /// Transactions submitted so far.
    pub submitted: u32,
    /// Transactions remaining.
    pub remaining: u32,
    /// Time elapsed since start.
    pub elapsed: Duration,
    /// Current submission rate (TPS).
    pub rate: f64,
    /// Estimated time remaining.
    pub eta: Duration,
}

impl std::fmt::Display for LoadProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let eta_secs = if self.eta == Duration::MAX {
            "∞".to_string()
        } else {
            format!("{:.1}s", self.eta.as_secs_f64())
        };

        write!(
            f,
            "{}: {} submitted, {} remaining, {:.1} TPS, ETA: {}",
            self.mode.name(),
            self.submitted,
            self.remaining,
            self.rate,
            eta_secs
        )
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_gen_mode() {
        assert!(!LoadGenMode::Pay.is_soroban());
        assert!(LoadGenMode::SorobanUpload.is_soroban());
        assert!(LoadGenMode::SorobanInvoke.is_soroban());
        assert!(LoadGenMode::MixedClassicSoroban.is_soroban());
        assert!(!LoadGenMode::PayPregenerated.is_soroban());
    }

    #[test]
    fn test_config_builder() {
        let config = GeneratedLoadConfig::new(LoadGenMode::Pay)
            .with_accounts(200)
            .with_txs(5000)
            .with_tx_rate(100)
            .with_offset(1000)
            .with_ledger_num(42);

        assert_eq!(config.mode, LoadGenMode::Pay);
        assert_eq!(config.n_accounts, 200);
        assert_eq!(config.n_txs, 5000);
        assert_eq!(config.tx_rate, 100);
        assert_eq!(config.offset, 1000);
        assert_eq!(config.ledger_num, 42);
    }

    #[test]
    fn test_txs_per_step() {
        let config = GeneratedLoadConfig::new(LoadGenMode::Pay)
            .with_tx_rate(100); // 100 TPS

        // With STEP_MSECS = 100ms, expect 10 txs per step
        assert_eq!(config.txs_per_step(), 10);

        let config = GeneratedLoadConfig::new(LoadGenMode::Pay)
            .with_tx_rate(5); // 5 TPS

        // Minimum 1 tx per step
        assert_eq!(config.txs_per_step(), 1);
    }

    #[test]
    fn test_metrics() {
        let mut metrics = LoadGenMetrics::new();
        metrics.start();

        metrics.record_submission(100);
        metrics.record_submission(100);
        metrics.record_bad_seq();
        metrics.record_low_fee(true);

        assert_eq!(metrics.txs_attempted, 4);
        assert_eq!(metrics.txs_submitted, 2);
        assert_eq!(metrics.txs_bad_seq, 1);
        assert_eq!(metrics.txs_low_fee, 1);
        assert_eq!(metrics.txs_skipped, 1);
        assert_eq!(metrics.bytes_sent, 200);
    }

    #[test]
    fn test_state_account_pool() {
        let mut state = LoadGeneratorState::new(10, 0);

        assert_eq!(state.accounts_available.len(), 10);
        assert!(state.accounts_in_use.is_empty());

        // Take accounts
        let a1 = state.take_account().unwrap();
        let a2 = state.take_account().unwrap();

        assert_eq!(state.accounts_available.len(), 8);
        assert_eq!(state.accounts_in_use.len(), 2);

        // Return one account
        state.return_account(a1);
        assert_eq!(state.accounts_available.len(), 9);
        assert_eq!(state.accounts_in_use.len(), 1);

        // Return all
        state.return_all_accounts();
        assert_eq!(state.accounts_available.len(), 10);
        assert!(state.accounts_in_use.is_empty());
    }

    #[test]
    fn test_load_generator_creation() {
        let config = TxGeneratorConfig::testnet();
        let generator = LoadGenerator::with_random_root(config);

        assert!(!generator.is_running());
        assert_eq!(generator.available_accounts(), 0);
    }

    #[test]
    fn test_start_stop() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = LoadGenerator::with_random_root(config);

        let load_config = GeneratedLoadConfig::new(LoadGenMode::Pay)
            .with_accounts(50)
            .with_txs(100);

        generator.start(&load_config);
        assert!(generator.is_running());
        assert_eq!(generator.available_accounts(), 50);

        generator.stop();
        assert!(!generator.is_running());
    }

    #[test]
    fn test_generate_step_pay() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = LoadGenerator::with_random_root(config);

        let load_config = GeneratedLoadConfig::new(LoadGenMode::Pay)
            .with_accounts(10)
            .with_txs(5)
            .with_tx_rate(100) // Would give 10 per step, but only 5 txs requested
            .with_ledger_num(1);

        generator.start(&load_config);

        let txs = generator.generate_step(&load_config);

        // Should generate up to 5 transactions (the total requested)
        assert!(txs.len() <= 5);
        assert!(txs.len() > 0);

        // Each tx should have a valid envelope
        for (source_id, envelope) in &txs {
            match envelope {
                TransactionEnvelope::Tx(env) => {
                    assert_eq!(env.tx.operations.len(), 1);
                }
                _ => panic!("Expected V1 envelope"),
            }
        }
    }

    #[test]
    fn test_generate_step_completion() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = LoadGenerator::with_random_root(config);

        let load_config = GeneratedLoadConfig::new(LoadGenMode::Pay)
            .with_accounts(100)
            .with_txs(5)
            .with_tx_rate(1000); // Generate many per step

        generator.start(&load_config);

        // First step should generate all 5
        let txs = generator.generate_step(&load_config);
        assert_eq!(txs.len(), 5);

        // No more transactions should be generated
        let txs = generator.generate_step(&load_config);
        assert!(txs.is_empty());
        assert!(!generator.is_running());
    }

    #[test]
    fn test_remaining_txs() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = LoadGenerator::with_random_root(config);

        let load_config = GeneratedLoadConfig::new(LoadGenMode::Pay)
            .with_accounts(100)
            .with_txs(10)
            .with_tx_rate(50);

        generator.start(&load_config);
        assert_eq!(generator.remaining_txs(&load_config), 10);

        // Generate some transactions
        let _txs = generator.generate_step(&load_config);
        assert!(generator.remaining_txs(&load_config) < 10);
    }

    #[test]
    fn test_progress_display() {
        let progress = LoadProgress {
            mode: LoadGenMode::Pay,
            submitted: 500,
            remaining: 500,
            elapsed: Duration::from_secs(10),
            rate: 50.0,
            eta: Duration::from_secs(10),
        };

        let display = format!("{}", progress);
        assert!(display.contains("PAY"));
        assert!(display.contains("500 submitted"));
        assert!(display.contains("500 remaining"));
        assert!(display.contains("50.0 TPS"));
    }

    #[test]
    fn test_spike_generation() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = LoadGenerator::with_random_root(config);

        let load_config = GeneratedLoadConfig::new(LoadGenMode::Pay)
            .with_accounts(100)
            .with_txs(100)
            .with_tx_rate(10) // 1 per step normally
            .with_spikes(Duration::from_millis(0), 5); // Immediate spike of 5

        generator.start(&load_config);

        // First step should include spike
        let txs = generator.generate_step(&load_config);
        assert!(txs.len() > 1); // More than base rate due to spike
    }

    #[test]
    fn test_account_offset() {
        let mut state = LoadGeneratorState::new(5, 1000);

        // Accounts should start at offset
        let a1 = state.take_account().unwrap();
        assert!(a1 >= 1000 && a1 < 1005);
    }
}
