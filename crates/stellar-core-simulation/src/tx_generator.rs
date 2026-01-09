//! Transaction generator for simulation testing.
//!
//! This module provides utilities for generating test transactions, primarily
//! for use in simulation and load testing scenarios. It matches the C++
//! `TxGenerator` class from `stellar-core/src/simulation/TxGenerator.cpp`.
//!
//! # Overview
//!
//! The [`TxGenerator`] creates transactions with deterministic account identities
//! and configurable fee rates. It supports:
//!
//! - Payment transactions between test accounts
//! - Deterministic account naming and sequence numbers
//! - Fee rate randomization within configurable bounds
//! - Account caching for efficient reuse
//!
//! # Example
//!
//! ```ignore
//! use stellar_core_simulation::tx_generator::{TxGenerator, TxGeneratorConfig};
//! use stellar_core_crypto::SecretKey;
//!
//! // Create generator with root account
//! let root_secret = SecretKey::generate();
//! let config = TxGeneratorConfig::testnet();
//! let mut generator = TxGenerator::new(root_secret, config);
//!
//! // Generate a payment transaction
//! let (source, tx) = generator.payment_transaction(
//!     100,     // num_accounts
//!     0,       // offset
//!     1,       // ledger_num
//!     0,       // source_account_id
//! );
//! ```

use rand::Rng;
use std::collections::HashMap;
use stellar_core_crypto::{sha256, SecretKey};
use stellar_xdr::curr::{
    AccountId, Asset, Hash, Memo, MuxedAccount, Operation, OperationBody, PaymentOp,
    Preconditions, PublicKey, SequenceNumber, Signature, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256,
};

// =============================================================================
// Constants
// =============================================================================

/// Special account ID for the root/master account.
pub const ROOT_ACCOUNT_ID: u64 = u64::MAX;

/// Default base fee in stroops.
pub const DEFAULT_BASE_FEE: u32 = 100;

/// Minimum balance for test accounts (in stroops).
pub const DEFAULT_MIN_BALANCE: i64 = 100_000_000; // 10 XLM

// =============================================================================
// TxGeneratorConfig
// =============================================================================

/// Configuration for the transaction generator.
#[derive(Debug, Clone)]
pub struct TxGeneratorConfig {
    /// Network passphrase for transaction signing.
    pub network_passphrase: String,
    /// Base fee per operation in stroops.
    pub base_fee: u32,
    /// Minimum balance for accounts in stroops.
    pub min_balance: i64,
    /// Maximum fee rate for randomized fees (if None, uses base_fee).
    pub max_fee_rate: Option<u32>,
}

impl TxGeneratorConfig {
    /// Creates a configuration for testnet.
    pub fn testnet() -> Self {
        Self {
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
            base_fee: DEFAULT_BASE_FEE,
            min_balance: DEFAULT_MIN_BALANCE,
            max_fee_rate: None,
        }
    }

    /// Creates a configuration for mainnet.
    pub fn mainnet() -> Self {
        Self {
            network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
            base_fee: DEFAULT_BASE_FEE,
            min_balance: DEFAULT_MIN_BALANCE,
            max_fee_rate: None,
        }
    }

    /// Creates a configuration with custom network passphrase.
    pub fn new(network_passphrase: impl Into<String>) -> Self {
        Self {
            network_passphrase: network_passphrase.into(),
            base_fee: DEFAULT_BASE_FEE,
            min_balance: DEFAULT_MIN_BALANCE,
            max_fee_rate: None,
        }
    }

    /// Sets the maximum fee rate for randomized fees.
    pub fn with_max_fee_rate(mut self, max_fee_rate: u32) -> Self {
        self.max_fee_rate = Some(max_fee_rate);
        self
    }

    /// Sets the base fee.
    pub fn with_base_fee(mut self, base_fee: u32) -> Self {
        self.base_fee = base_fee;
        self
    }
}

impl Default for TxGeneratorConfig {
    fn default() -> Self {
        Self::testnet()
    }
}

// =============================================================================
// TestAccount
// =============================================================================

/// A test account with tracked sequence number.
///
/// This wraps a keypair with sequence number tracking for transaction
/// generation. The sequence number is automatically incremented when
/// generating transactions.
#[derive(Debug, Clone)]
pub struct TestAccount {
    /// The account's secret key.
    secret: SecretKey,
    /// Current sequence number.
    sequence_number: i64,
    /// Account ID (for caching).
    account_id: u64,
}

impl TestAccount {
    /// Creates a new test account with the given secret and initial sequence number.
    pub fn new(secret: SecretKey, initial_seq: i64, account_id: u64) -> Self {
        Self {
            secret,
            sequence_number: initial_seq,
            account_id,
        }
    }

    /// Creates a test account with a deterministic name-based key.
    ///
    /// The secret key is derived from SHA-256 of the account name.
    pub fn from_name(name: &str, initial_seq: i64, account_id: u64) -> Self {
        let seed = derive_seed_from_name(name);
        let secret = SecretKey::from_seed(&seed);
        Self::new(secret, initial_seq, account_id)
    }

    /// Returns the secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// Returns the public key.
    pub fn public_key(&self) -> stellar_xdr::curr::PublicKey {
        let pk = self.secret.public_key();
        PublicKey::PublicKeyTypeEd25519(Uint256(*pk.as_bytes()))
    }

    /// Returns the account ID as XDR type.
    pub fn account_id_xdr(&self) -> AccountId {
        AccountId(self.public_key())
    }

    /// Returns the muxed account (non-muxed form).
    pub fn muxed_account(&self) -> MuxedAccount {
        MuxedAccount::Ed25519(Uint256(*self.secret.public_key().as_bytes()))
    }

    /// Returns the current sequence number.
    pub fn sequence_number(&self) -> i64 {
        self.sequence_number
    }

    /// Increments and returns the next sequence number.
    ///
    /// This should be called when creating a new transaction.
    pub fn next_sequence_number(&mut self) -> i64 {
        self.sequence_number += 1;
        self.sequence_number
    }

    /// Sets the sequence number explicitly.
    ///
    /// Use this after loading the account from the ledger.
    pub fn set_sequence_number(&mut self, seq: i64) {
        self.sequence_number = seq;
    }

    /// Returns the numeric account ID.
    pub fn id(&self) -> u64 {
        self.account_id
    }
}

// =============================================================================
// TxGenerator
// =============================================================================

/// A transaction generator for simulation testing.
///
/// This generator creates test transactions with deterministic account
/// identities and configurable fee rates. Accounts are cached for
/// efficient reuse across multiple transaction generations.
pub struct TxGenerator {
    /// Configuration.
    config: TxGeneratorConfig,
    /// Root account (master secret).
    root: TestAccount,
    /// Cached test accounts.
    accounts: HashMap<u64, TestAccount>,
    /// Network ID hash for transaction signing.
    network_id: Hash,
    /// Random number generator.
    rng: rand::rngs::ThreadRng,
}

impl TxGenerator {
    /// Creates a new transaction generator with the given root secret.
    pub fn new(root_secret: SecretKey, config: TxGeneratorConfig) -> Self {
        let network_id = compute_network_id(&config.network_passphrase);
        let root = TestAccount::new(root_secret, 0, ROOT_ACCOUNT_ID);

        Self {
            config,
            root,
            accounts: HashMap::new(),
            network_id,
            rng: rand::thread_rng(),
        }
    }

    /// Creates a generator with a randomly generated root account.
    pub fn with_random_root(config: TxGeneratorConfig) -> Self {
        let root_secret = SecretKey::generate();
        Self::new(root_secret, config)
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &TxGeneratorConfig {
        &self.config
    }

    /// Returns a reference to the root account.
    pub fn root(&self) -> &TestAccount {
        &self.root
    }

    /// Returns a mutable reference to the root account.
    pub fn root_mut(&mut self) -> &mut TestAccount {
        &mut self.root
    }

    /// Returns the network ID hash.
    pub fn network_id(&self) -> &Hash {
        &self.network_id
    }

    /// Finds or creates an account by ID.
    ///
    /// For `ROOT_ACCOUNT_ID`, returns the root account.
    /// For other IDs, creates a deterministically-named test account.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The numeric account identifier
    /// * `ledger_num` - Current ledger number (used for initial sequence)
    pub fn find_account(&mut self, account_id: u64, ledger_num: u32) -> &TestAccount {
        if account_id == ROOT_ACCOUNT_ID {
            return &self.root;
        }

        if !self.accounts.contains_key(&account_id) {
            // Initial sequence number: ledger_num in high 32 bits
            let initial_seq = (ledger_num as i64) << 32;
            let name = format!("TestAccount-{}", account_id);
            let account = TestAccount::from_name(&name, initial_seq, account_id);
            self.accounts.insert(account_id, account);
        }

        self.accounts.get(&account_id).unwrap()
    }

    /// Finds or creates an account by ID (mutable).
    pub fn find_account_mut(&mut self, account_id: u64, ledger_num: u32) -> &mut TestAccount {
        if account_id == ROOT_ACCOUNT_ID {
            return &mut self.root;
        }

        if !self.accounts.contains_key(&account_id) {
            let initial_seq = (ledger_num as i64) << 32;
            let name = format!("TestAccount-{}", account_id);
            let account = TestAccount::from_name(&name, initial_seq, account_id);
            self.accounts.insert(account_id, account);
        }

        self.accounts.get_mut(&account_id).unwrap()
    }

    /// Generates a fee based on the configuration.
    ///
    /// If `max_fee_rate` is set, generates a random fee between
    /// `base_fee` and `max_fee_rate`. Otherwise uses `base_fee`.
    pub fn generate_fee(&mut self, ops_count: usize) -> u32 {
        let base = self.config.base_fee;

        if let Some(max_rate) = self.config.max_fee_rate {
            if max_rate > base {
                let rate = self.rng.gen_range(base..=max_rate);
                let base_amount = (ops_count as u32) * rate;
                // Add fractional component for realism
                let fractional = self.rng.gen_range(0..ops_count) as u32;
                return base_amount + fractional;
            }
        }

        (ops_count as u32) * base
    }

    /// Generates a payment transaction.
    ///
    /// Creates a payment of 1 stroop from the source account to a randomly
    /// selected destination account.
    ///
    /// # Arguments
    ///
    /// * `num_accounts` - Number of accounts in the destination pool
    /// * `offset` - Starting offset for destination account IDs
    /// * `ledger_num` - Current ledger number
    /// * `source_account_id` - Source account ID
    ///
    /// # Returns
    ///
    /// A tuple of (source account ID, signed transaction envelope).
    pub fn payment_transaction(
        &mut self,
        num_accounts: u32,
        offset: u32,
        ledger_num: u32,
        source_account_id: u64,
    ) -> (u64, TransactionEnvelope) {
        // Pick destination account
        let dest_account_id = self.rng.gen_range(0..num_accounts) as u64 + offset as u64;

        // Get accounts
        let dest_public_key = {
            let dest = self.find_account(dest_account_id, ledger_num);
            dest.public_key()
        };

        let source = self.find_account_mut(source_account_id, ledger_num);
        let source_muxed = source.muxed_account();
        let seq_num = source.next_sequence_number();
        let source_secret = source.secret_key().clone();

        // Create payment operation (1 stroop of native XLM)
        let payment_op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256(
                    match dest_public_key {
                        PublicKey::PublicKeyTypeEd25519(pk) => pk.0,
                    },
                )),
                asset: Asset::Native,
                amount: 1, // 1 stroop
            }),
        };

        // Generate fee
        let fee = self.generate_fee(1);

        // Build transaction
        let tx = self.build_transaction(source_muxed, seq_num, vec![payment_op], fee);

        // Sign transaction
        let envelope = self.sign_transaction(tx, &source_secret);

        (source_account_id, envelope)
    }

    /// Generates a create account transaction.
    ///
    /// Creates a new account with the specified starting balance.
    ///
    /// # Arguments
    ///
    /// * `source_account_id` - Source account ID (funds provider)
    /// * `new_account_id` - ID for the new account
    /// * `starting_balance` - Starting balance in stroops
    /// * `ledger_num` - Current ledger number
    pub fn create_account_transaction(
        &mut self,
        source_account_id: u64,
        new_account_id: u64,
        starting_balance: i64,
        ledger_num: u32,
    ) -> (u64, TransactionEnvelope) {
        // Get the new account's public key (creates it if needed)
        let new_public_key = {
            let new_account = self.find_account(new_account_id, ledger_num);
            new_account.public_key()
        };

        let source = self.find_account_mut(source_account_id, ledger_num);
        let source_muxed = source.muxed_account();
        let seq_num = source.next_sequence_number();
        let source_secret = source.secret_key().clone();

        // Create account operation
        let create_op = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(stellar_xdr::curr::CreateAccountOp {
                destination: AccountId(new_public_key),
                starting_balance,
            }),
        };

        let fee = self.generate_fee(1);
        let tx = self.build_transaction(source_muxed, seq_num, vec![create_op], fee);
        let envelope = self.sign_transaction(tx, &source_secret);

        (source_account_id, envelope)
    }

    /// Builds a transaction from operations.
    fn build_transaction(
        &self,
        source_account: MuxedAccount,
        seq_num: i64,
        operations: Vec<Operation>,
        fee: u32,
    ) -> Transaction {
        Transaction {
            source_account,
            fee,
            seq_num: SequenceNumber(seq_num),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: operations.try_into().expect("operations should fit"),
            ext: TransactionExt::V0,
        }
    }

    /// Signs a transaction and wraps it in an envelope.
    fn sign_transaction(&self, tx: Transaction, secret: &SecretKey) -> TransactionEnvelope {
        // Compute transaction hash for signing
        let tx_hash = compute_transaction_hash(&self.network_id, &tx);

        // Sign the hash
        let signature_bytes = secret.sign(&tx_hash);

        // Create decorated signature with hint
        let hint = signature_hint(secret);
        let decorated_sig = stellar_xdr::curr::DecoratedSignature {
            hint: stellar_xdr::curr::SignatureHint(hint),
            signature: Signature(signature_bytes.0.to_vec().try_into().expect("signature fits")),
        };

        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: vec![decorated_sig].try_into().expect("signatures fit"),
        })
    }

    /// Returns the number of cached accounts.
    pub fn cached_account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Clears the account cache.
    pub fn clear_cache(&mut self) {
        self.accounts.clear();
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Derives a 32-byte seed from an account name using SHA-256.
fn derive_seed_from_name(name: &str) -> [u8; 32] {
    *sha256(name.as_bytes()).as_bytes()
}

/// Computes the network ID hash from the passphrase.
fn compute_network_id(passphrase: &str) -> Hash {
    Hash(*sha256(passphrase.as_bytes()).as_bytes())
}

/// Computes the transaction hash for signing.
fn compute_transaction_hash(network_id: &Hash, tx: &Transaction) -> [u8; 32] {
    use stellar_xdr::curr::{Limits, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction, WriteXdr};

    let payload = TransactionSignaturePayload {
        network_id: network_id.clone(),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };

    let xdr_bytes = payload
        .to_xdr(Limits::none())
        .expect("transaction payload serialization");

    *sha256(&xdr_bytes).as_bytes()
}

/// Computes the signature hint (last 4 bytes of public key).
fn signature_hint(secret: &SecretKey) -> [u8; 4] {
    let public_key = secret.public_key();
    let pk_bytes = public_key.as_bytes();
    let mut hint = [0u8; 4];
    hint.copy_from_slice(&pk_bytes[28..32]);
    hint
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = TxGeneratorConfig::testnet();
        assert_eq!(config.base_fee, DEFAULT_BASE_FEE);
        assert!(config.network_passphrase.contains("Test"));

        let config = TxGeneratorConfig::mainnet();
        assert!(config.network_passphrase.contains("Public"));
    }

    #[test]
    fn test_test_account_creation() {
        let secret = SecretKey::generate();
        let account = TestAccount::new(secret, 100, 1);
        assert_eq!(account.sequence_number(), 100);
        assert_eq!(account.id(), 1);
    }

    #[test]
    fn test_test_account_from_name() {
        let account1 = TestAccount::from_name("TestAccount-0", 0, 0);
        let account2 = TestAccount::from_name("TestAccount-0", 0, 0);

        // Same name should produce same public key
        assert_eq!(
            account1.public_key(),
            account2.public_key()
        );

        // Different names should produce different keys
        let account3 = TestAccount::from_name("TestAccount-1", 0, 1);
        assert_ne!(
            account1.public_key(),
            account3.public_key()
        );
    }

    #[test]
    fn test_sequence_number_increment() {
        let secret = SecretKey::generate();
        let mut account = TestAccount::new(secret, 100, 1);

        assert_eq!(account.sequence_number(), 100);
        assert_eq!(account.next_sequence_number(), 101);
        assert_eq!(account.next_sequence_number(), 102);
        assert_eq!(account.sequence_number(), 102);
    }

    #[test]
    fn test_generator_creation() {
        let config = TxGeneratorConfig::testnet();
        let generator = TxGenerator::with_random_root(config);

        assert_eq!(generator.cached_account_count(), 0);
    }

    #[test]
    fn test_find_account() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = TxGenerator::with_random_root(config);

        // First access creates the account
        let _account = generator.find_account(0, 100);
        assert_eq!(generator.cached_account_count(), 1);

        // Second access returns cached account
        let _account = generator.find_account(0, 100);
        assert_eq!(generator.cached_account_count(), 1);

        // Different ID creates new account
        let _account = generator.find_account(1, 100);
        assert_eq!(generator.cached_account_count(), 2);
    }

    #[test]
    fn test_find_root_account() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = TxGenerator::with_random_root(config);

        // Root account should not be added to cache
        let _root = generator.find_account(ROOT_ACCOUNT_ID, 100);
        assert_eq!(generator.cached_account_count(), 0);
    }

    #[test]
    fn test_initial_sequence_number() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = TxGenerator::with_random_root(config);

        let ledger_num = 1000u32;
        let account = generator.find_account(0, ledger_num);

        // Initial sequence should be ledger_num << 32
        let expected = (ledger_num as i64) << 32;
        assert_eq!(account.sequence_number(), expected);
    }

    #[test]
    fn test_generate_fee_base() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = TxGenerator::with_random_root(config);

        let fee = generator.generate_fee(1);
        assert_eq!(fee, DEFAULT_BASE_FEE);

        let fee = generator.generate_fee(3);
        assert_eq!(fee, DEFAULT_BASE_FEE * 3);
    }

    #[test]
    fn test_generate_fee_with_max() {
        let config = TxGeneratorConfig::testnet().with_max_fee_rate(1000);
        let mut generator = TxGenerator::with_random_root(config);

        // Generate multiple fees - should be in range
        for _ in 0..10 {
            let fee = generator.generate_fee(1);
            assert!(fee >= DEFAULT_BASE_FEE);
            assert!(fee <= 1000);
        }
    }

    #[test]
    fn test_payment_transaction() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = TxGenerator::with_random_root(config);

        let (source_id, envelope) = generator.payment_transaction(
            100, // num_accounts
            0,   // offset
            1,   // ledger_num
            ROOT_ACCOUNT_ID, // source
        );

        assert_eq!(source_id, ROOT_ACCOUNT_ID);

        // Check envelope structure
        match envelope {
            TransactionEnvelope::Tx(env) => {
                assert_eq!(env.tx.operations.len(), 1);
                assert_eq!(env.tx.fee, DEFAULT_BASE_FEE);
                assert_eq!(env.signatures.len(), 1);

                // Check it's a payment operation
                match &env.tx.operations[0].body {
                    OperationBody::Payment(op) => {
                        assert_eq!(op.amount, 1); // 1 stroop
                        assert!(matches!(op.asset, Asset::Native));
                    }
                    _ => panic!("Expected payment operation"),
                }
            }
            _ => panic!("Expected V1 envelope"),
        }
    }

    #[test]
    fn test_create_account_transaction() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = TxGenerator::with_random_root(config);

        let starting_balance = 100_000_000i64; // 10 XLM
        let (source_id, envelope) = generator.create_account_transaction(
            ROOT_ACCOUNT_ID,
            0, // new account
            starting_balance,
            1,
        );

        assert_eq!(source_id, ROOT_ACCOUNT_ID);

        match envelope {
            TransactionEnvelope::Tx(env) => {
                assert_eq!(env.tx.operations.len(), 1);

                match &env.tx.operations[0].body {
                    OperationBody::CreateAccount(op) => {
                        assert_eq!(op.starting_balance, starting_balance);
                    }
                    _ => panic!("Expected create account operation"),
                }
            }
            _ => panic!("Expected V1 envelope"),
        }
    }

    #[test]
    fn test_deterministic_accounts() {
        // Create two generators and verify they produce same accounts
        let config1 = TxGeneratorConfig::testnet();
        let config2 = TxGeneratorConfig::testnet();

        let mut gen1 = TxGenerator::with_random_root(config1);
        let mut gen2 = TxGenerator::with_random_root(config2);

        // Account 0 should have same public key in both
        let pk1 = gen1.find_account(0, 1).public_key();
        let pk2 = gen2.find_account(0, 1).public_key();

        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_network_id_computation() {
        let testnet_id = compute_network_id("Test SDF Network ; September 2015");
        let mainnet_id = compute_network_id("Public Global Stellar Network ; September 2015");

        // Should be different
        assert_ne!(testnet_id.0, mainnet_id.0);

        // Should be 32 bytes
        assert_eq!(testnet_id.0.len(), 32);
    }

    #[test]
    fn test_clear_cache() {
        let config = TxGeneratorConfig::testnet();
        let mut generator = TxGenerator::with_random_root(config);

        generator.find_account(0, 1);
        generator.find_account(1, 1);
        assert_eq!(generator.cached_account_count(), 2);

        generator.clear_cache();
        assert_eq!(generator.cached_account_count(), 0);
    }
}
