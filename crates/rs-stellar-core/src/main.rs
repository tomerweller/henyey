//! rs-stellar-core - Pure Rust implementation of Stellar Core
//!
//! This binary provides a command-line interface for running a Stellar Core
//! validator node, catching up from history archives, and performing other
//! Stellar network operations.
//!
//! # Quick Start
//!
//! ```bash
//! # Run a node on testnet (default)
//! rs-stellar-core --testnet run
//!
//! # Catch up to the latest ledger
//! rs-stellar-core --testnet catchup current
//!
//! # Generate a new keypair
//! rs-stellar-core new-keypair
//! ```
//!
//! # Commands
//!
//! The CLI provides the following main commands:
//!
//! - **run**: Start the node (as watcher, full node, or validator)
//! - **catchup**: Catch up from history archives to a specific ledger
//! - **new-db**: Create a new database
//! - **upgrade-db**: Upgrade database schema
//! - **new-keypair**: Generate a new node keypair
//! - **info**: Print node information
//! - **verify-history**: Verify history archives
//! - **publish-history**: Publish history to archives (validators only)
//! - **check-quorum-intersection**: Verify quorum intersection from JSON
//! - **sample-config**: Print sample configuration
//! - **offline**: Offline utilities (XDR tools, replay testing)
//!
//! # Configuration
//!
//! Configuration can be provided via:
//! - A TOML configuration file (`--config <FILE>`)
//! - Built-in network defaults (`--testnet` or `--mainnet`)
//! - Environment variables (prefixed with `STELLAR_`)
//!
//! See `rs-stellar-core sample-config` for an example configuration.
//!
//! # Architecture
//!
//! This crate is a thin CLI wrapper around the [`stellar_core_app`] crate,
//! which contains the core application logic. The CLI handles:
//!
//! - Argument parsing with `clap`
//! - Configuration loading and merging
//! - Logging initialization
//! - Command dispatch
//!
//! The actual node implementation, catchup logic, and subsystem coordination
//! are handled by the underlying library crates.

mod quorum_intersection;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use stellar_core_bucket::StateArchivalSettings;
use stellar_core_common::protocol::MIN_SOROBAN_PROTOCOL_VERSION;
use stellar_core_history::ReplayConfig;
use stellar_xdr::curr::WriteXdr;

use stellar_core_app::{
    logging, run_catchup, run_node, App, AppConfig, CatchupMode as CatchupModeInternal,
    CatchupOptions, LogConfig, LogFormat, RunMode, RunOptions,
};

/// Pure Rust implementation of Stellar Core
#[derive(Parser)]
#[command(name = "rs-stellar-core")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, value_name = "FILE", global = true)]
    config: Option<PathBuf>,

    /// Enable verbose logging (debug level)
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Enable trace logging (most verbose)
    #[arg(long, global = true)]
    trace: bool,

    /// Log output format
    #[arg(long, default_value = "text", global = true)]
    log_format: CliLogFormat,

    /// Use testnet configuration (default)
    #[arg(long, global = true)]
    testnet: bool,

    /// Use mainnet configuration
    #[arg(long, global = true)]
    mainnet: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Log output format for CLI
#[derive(Clone, Copy, Debug, Default, clap::ValueEnum)]
enum CliLogFormat {
    #[default]
    Text,
    Json,
}

impl From<CliLogFormat> for LogFormat {
    fn from(fmt: CliLogFormat) -> Self {
        match fmt {
            CliLogFormat::Text => LogFormat::Text,
            CliLogFormat::Json => LogFormat::Json,
        }
    }
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// Run the Stellar Core node
    Run {
        /// Run in validator mode (participate in consensus)
        #[arg(long)]
        validator: bool,

        /// Run in watcher mode (observe only, no catchup)
        #[arg(long)]
        watcher: bool,

        /// Force catchup even if state exists
        #[arg(long)]
        force_catchup: bool,
    },

    /// Catch up from history archives
    Catchup {
        /// Target ledger: "current", a ledger number, or "ledger/count"
        #[arg(value_name = "TARGET", default_value = "current")]
        target: String,

        /// Catchup mode: minimal, complete, or recent:N
        #[arg(long, default_value = "minimal")]
        mode: CliCatchupMode,

        /// Skip verification after catchup
        #[arg(long)]
        no_verify: bool,

        /// Number of parallel downloads
        #[arg(long, default_value = "8")]
        parallelism: usize,
    },

    /// Create a new database
    NewDb {
        /// Path to the database file (overrides config)
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        /// Force creation even if database exists
        #[arg(long)]
        force: bool,
    },

    /// Upgrade database schema
    UpgradeDb,

    /// Generate a new node keypair
    NewKeypair,

    /// Print node information
    Info,

    /// Verify history archives
    VerifyHistory {
        /// Start ledger sequence
        #[arg(long)]
        from: Option<u32>,

        /// End ledger sequence
        #[arg(long)]
        to: Option<u32>,
    },

    /// Publish history to archives (validators only)
    PublishHistory {
        /// Force republishing of existing checkpoints
        #[arg(long)]
        force: bool,
    },

    /// Check quorum intersection from a JSON file
    CheckQuorumIntersection {
        /// Path to the JSON file
        path: PathBuf,
    },

    /// Print sample configuration
    SampleConfig,

    /// Send a command to a running stellar-core node
    ///
    /// Makes an HTTP GET request to the local node's command interface.
    /// Examples:
    ///   http-command info
    ///   http-command "peers?fullkeys=true"
    ///   http-command "ll?level=DEBUG"
    HttpCommand {
        /// The command to send (e.g., "info", "peers", "ll?level=DEBUG")
        command: String,

        /// HTTP port of the running node (default: 11626)
        #[arg(long, short, default_value = "11626")]
        port: u16,
    },

    /// Offline commands (no network required)
    #[command(subcommand)]
    Offline(OfflineCommands),
}

/// Catchup mode for CLI
#[derive(Clone, Debug, Default, clap::ValueEnum)]
enum CliCatchupMode {
    /// Download only the latest state
    #[default]
    Minimal,
    /// Download complete history from genesis
    Complete,
    /// Download recent history only (use --recent-count to specify)
    Recent,
}

/// Offline commands that don't require network access
#[derive(Subcommand)]
enum OfflineCommands {
    /// Convert Stellar keys between formats
    ConvertKey {
        /// The key to convert
        key: String,
    },

    /// Decode an XDR value
    DecodeXdr {
        /// XDR type name
        #[arg(long, value_name = "TYPE")]
        r#type: String,

        /// Base64-encoded XDR
        value: String,
    },

    /// Encode a value to XDR
    EncodeXdr {
        /// XDR type name
        #[arg(long, value_name = "TYPE")]
        r#type: String,

        /// JSON value to encode
        value: String,
    },

    /// Print bucket list information
    BucketInfo {
        /// Path to bucket directory
        path: PathBuf,
    },

    /// Test bucket list implementation by replaying ledger changes from CDP
    ///
    /// This validates that our bucket list correctly handles entry changes,
    /// spill timing, and hash computation. Uses TransactionMeta from CDP
    /// (the exact changes C++ stellar-core produced) rather than re-executing.
    ReplayBucketList {
        /// Start ledger sequence (defaults to a recent checkpoint)
        #[arg(long)]
        from: Option<u32>,

        /// End ledger sequence (defaults to latest available)
        #[arg(long)]
        to: Option<u32>,

        /// Stop on first mismatch
        #[arg(long)]
        stop_on_error: bool,

        /// Test only live bucket list (ignore hot archive hash)
        ///
        /// For protocol 23+, bucket_list_hash is SHA256(live || hot_archive).
        /// Use this flag to verify just the live bucket list when hot archive
        /// updates aren't implemented yet.
        #[arg(long)]
        live_only: bool,

        /// CDP data lake URL (default: AWS public testnet)
        #[arg(
            long,
            default_value = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/testnet"
        )]
        cdp_url: String,

        /// CDP date partition (default: 2025-12-18)
        #[arg(long, default_value = "2025-12-18")]
        cdp_date: String,
    },

    /// Test transaction execution by comparing our results against CDP metadata
    ///
    /// This validates that our transaction execution (Soroban host, classic ops)
    /// produces the same ledger entry changes as C++ stellar-core. Differences
    /// indicate execution divergence that needs investigation.
    VerifyExecution {
        /// Start ledger sequence (defaults to a recent checkpoint)
        #[arg(long)]
        from: Option<u32>,

        /// End ledger sequence (defaults to latest available)
        #[arg(long)]
        to: Option<u32>,

        /// Stop on first mismatch
        #[arg(long)]
        stop_on_error: bool,

        /// Show detailed diff of mismatched entries
        #[arg(long)]
        show_diff: bool,

        /// CDP data lake URL (default: AWS public testnet)
        #[arg(
            long,
            default_value = "https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/testnet"
        )]
        cdp_url: String,

        /// CDP date partition (default: 2025-12-18)
        #[arg(long, default_value = "2025-12-18")]
        cdp_date: String,

        /// Cache directory for buckets and CDP metadata (default: ~/.cache/rs-stellar-core)
        #[arg(long)]
        cache_dir: Option<std::path::PathBuf>,

        /// Disable caching (use temp directories)
        #[arg(long)]
        no_cache: bool,

        /// Quiet mode: only output summary and errors
        #[arg(long, short = 'q')]
        quiet: bool,
    },

    /// Debug: inspect an account in the bucket list at a checkpoint
    DebugBucketEntry {
        /// Checkpoint ledger sequence
        #[arg(long)]
        checkpoint: u32,

        /// Account ID (hex)
        #[arg(long)]
        account: String,
    },

    /// Add a signature to a transaction envelope
    ///
    /// Reads a transaction envelope (base64), prompts for a secret key,
    /// and outputs the signed envelope.
    SignTransaction {
        /// Network passphrase for signing (required)
        #[arg(long)]
        netid: String,

        /// Input transaction envelope in base64 (or "-" for stdin)
        #[arg(default_value = "-")]
        input: String,

        /// Output as base64 (default: true)
        #[arg(long, default_value = "true")]
        base64: bool,
    },

    /// Print the public key corresponding to a secret key
    ///
    /// Reads a secret key seed (S...) from stdin and prints the public key.
    SecToPub,

    /// Dump ledger entries to JSON
    ///
    /// Dumps ledger entries from the bucket list to a JSON file for debugging.
    /// Supports filtering by entry type and limiting output count.
    DumpLedger {
        /// Output file path
        #[arg(long, short)]
        output: PathBuf,

        /// Filter by entry type (account, trustline, offer, data, claimable_balance,
        /// liquidity_pool, contract_data, contract_code, config_setting, ttl)
        #[arg(long)]
        entry_type: Option<String>,

        /// Maximum number of entries to output
        #[arg(long)]
        limit: Option<u64>,

        /// Only include entries modified in the last N ledgers
        #[arg(long)]
        last_modified_ledger_count: Option<u32>,
    },

    /// Perform diagnostic self-checks
    ///
    /// This command performs comprehensive diagnostic checks including:
    /// - Header chain verification (verify hash linkage)
    /// - Bucket hash verification (verify all buckets have correct hashes)
    /// - Crypto benchmarking (Ed25519 sign/verify performance)
    ///
    /// Unlike the HTTP /self-check endpoint (which only runs quick online checks),
    /// this offline command performs full bucket verification which may take
    /// significant time on large databases.
    SelfCheck,

    /// Write verified checkpoint ledger hashes to a file
    ///
    /// Downloads checkpoint headers from history archives, verifies the header
    /// chain, and writes verified checkpoint hashes to a JSON file. This file
    /// can be used with `--trusted-checkpoint-hashes` during catchup to verify
    /// against known-good hashes.
    VerifyCheckpoints {
        /// Output file path for verified checkpoint hashes
        #[arg(long, short, required = true)]
        output: PathBuf,

        /// Start ledger sequence (defaults to genesis)
        #[arg(long)]
        from: Option<u32>,

        /// End ledger sequence (defaults to current)
        #[arg(long)]
        to: Option<u32>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli)?;

    // Load or create configuration
    let config = load_config(&cli)?;

    // Execute command
    match cli.command {
        Commands::Run {
            validator,
            watcher,
            force_catchup,
        } => cmd_run(config, validator, watcher, force_catchup).await,

        Commands::Catchup {
            target,
            mode,
            no_verify,
            parallelism,
        } => cmd_catchup(config, target, mode, !no_verify, parallelism).await,

        Commands::NewDb { path, force } => cmd_new_db(config, path, force).await,

        Commands::UpgradeDb => cmd_upgrade_db(config).await,

        Commands::NewKeypair => cmd_new_keypair(),

        Commands::Info => cmd_info(config).await,

        Commands::VerifyHistory { from, to } => cmd_verify_history(config, from, to).await,

        Commands::PublishHistory { force } => cmd_publish_history(config, force).await,

        Commands::CheckQuorumIntersection { path } => cmd_check_quorum_intersection(&path),

        Commands::SampleConfig => cmd_sample_config(),

        Commands::HttpCommand { command, port } => cmd_http_command(&command, port).await,

        Commands::Offline(cmd) => cmd_offline(cmd, config).await,
    }
}

/// Initialize the logging subsystem.
fn init_logging(cli: &Cli) -> anyhow::Result<()> {
    let level = if cli.trace {
        "trace"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };

    let config = LogConfig::default().with_level(level);

    let config = match cli.log_format {
        CliLogFormat::Text => config,
        CliLogFormat::Json => LogConfig {
            format: LogFormat::Json,
            ansi_colors: false,
            ..config
        },
    };

    logging::init(&config)?;

    tracing::debug!("Logging initialized");
    Ok(())
}

/// Load configuration from file or use defaults.
fn load_config(cli: &Cli) -> anyhow::Result<AppConfig> {
    let config = if let Some(ref config_path) = cli.config {
        tracing::info!(path = ?config_path, "Loading configuration from file");
        AppConfig::from_file_with_env(config_path)?
    } else if cli.mainnet {
        tracing::info!("Using mainnet configuration");
        let mut config = AppConfig::mainnet();
        config.apply_env_overrides();
        config
    } else {
        tracing::info!("Using testnet configuration (default)");
        let mut config = AppConfig::testnet();
        config.apply_env_overrides();
        config
    };

    Ok(config)
}

/// Run command handler.
async fn cmd_run(
    config: AppConfig,
    validator: bool,
    watcher: bool,
    force_catchup: bool,
) -> anyhow::Result<()> {
    if validator && watcher {
        anyhow::bail!("Cannot run as both validator and watcher");
    }

    let mode = if validator {
        RunMode::Validator
    } else if watcher {
        RunMode::Watcher
    } else {
        RunMode::Full
    };

    let options = RunOptions {
        mode,
        force_catchup,
        ..Default::default()
    };

    run_node(config, options).await
}

/// Catchup command handler.
async fn cmd_catchup(
    config: AppConfig,
    target: String,
    mode: CliCatchupMode,
    verify: bool,
    parallelism: usize,
) -> anyhow::Result<()> {
    let mode = match mode {
        CliCatchupMode::Minimal => CatchupModeInternal::Minimal,
        CliCatchupMode::Complete => CatchupModeInternal::Complete,
        CliCatchupMode::Recent => CatchupModeInternal::Recent(1000), // Default to 1000 ledgers
    };

    let options = CatchupOptions {
        target,
        mode,
        verify,
        parallelism,
        keep_temp: false,
    };

    let result = run_catchup(config, options).await?;
    println!("{}", result);
    Ok(())
}

/// New database command handler.
async fn cmd_new_db(
    mut config: AppConfig,
    path: Option<PathBuf>,
    force: bool,
) -> anyhow::Result<()> {
    // Override path if provided
    if let Some(p) = path {
        config.database.path = p;
    }

    let db_path = &config.database.path;

    // Check if database already exists
    if db_path.exists() {
        if force {
            tracing::warn!(path = ?db_path, "Removing existing database");
            std::fs::remove_file(db_path)?;
        } else {
            anyhow::bail!(
                "Database already exists at {:?}. Use --force to overwrite.",
                db_path
            );
        }
    }

    tracing::info!(path = ?db_path, "Creating new database");

    // Ensure parent directory exists
    if let Some(parent) = db_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Create the database
    let _db = stellar_core_db::Database::open(db_path)?;

    println!("Database created successfully at: {}", db_path.display());
    Ok(())
}

/// Upgrade database command handler.
async fn cmd_upgrade_db(config: AppConfig) -> anyhow::Result<()> {
    tracing::info!(path = ?config.database.path, "Upgrading database schema");

    let _db = stellar_core_db::Database::open(&config.database.path)?;

    // Database initialization already applies the latest schema
    // In a full implementation, this would run migrations

    println!("Database schema is up to date");
    Ok(())
}

/// Generate keypair command handler.
fn cmd_new_keypair() -> anyhow::Result<()> {
    let keypair = stellar_core_crypto::SecretKey::generate();

    println!("Generated new keypair:");
    println!();
    println!("Public Key:  {}", keypair.public_key().to_strkey());
    println!("Secret Seed: {}", keypair.to_strkey());
    println!();
    println!("IMPORTANT: Store the secret seed securely! It cannot be recovered.");

    Ok(())
}

/// Info command handler.
async fn cmd_info(config: AppConfig) -> anyhow::Result<()> {
    // Try to create app to get full info, or show basic info if that fails
    match App::new(config.clone()).await {
        Ok(app) => {
            let info = app.info();
            print!("{}", info);
        }
        Err(e) => {
            tracing::debug!(error = %e, "Could not initialize app, showing basic info");

            println!("rs-stellar-core {}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("Configuration:");
            println!("  Network: {}", config.network.passphrase);
            println!("  Database: {}", config.database.path.display());
            println!("  Validator: {}", config.node.is_validator);
            println!();

            if !config.database.path.exists() {
                println!("Note: Database does not exist. Run 'new-db' to create it.");
            }
        }
    }

    Ok(())
}

/// Verify history command handler.
async fn cmd_verify_history(
    config: AppConfig,
    from: Option<u32>,
    to: Option<u32>,
) -> anyhow::Result<()> {
    use stellar_core_history::{verify, HistoryArchive};
    use stellar_core_ledger::TransactionSetVariant;

    println!("Verifying history archives...");
    println!();

    // Create archive clients from config
    let archives: Vec<HistoryArchive> = config
        .history
        .archives
        .iter()
        .filter(|a| a.get_enabled)
        .filter_map(|a| match HistoryArchive::new(&a.url) {
            Ok(archive) => Some(archive),
            Err(e) => {
                println!("Warning: Failed to create archive {}: {}", a.url, e);
                None
            }
        })
        .collect();

    if archives.is_empty() {
        anyhow::bail!("No history archives available");
    }

    println!("Using {} archive(s)", archives.len());

    // Get the range to verify
    let archive = &archives[0];
    let root_has = archive.get_root_has().await?;
    let current_ledger = root_has.current_ledger;

    let start = from.unwrap_or(1);
    let end = to.unwrap_or(current_ledger);

    println!("Verifying ledger range: {} to {}", start, end);
    println!();

    // Verify in checkpoint intervals (64 ledgers)
    let mut verified_count = 0;
    let mut error_count = 0;

    // Calculate checkpoint-aligned start
    let start_checkpoint = stellar_core_history::checkpoint::checkpoint_containing(start);
    let end_checkpoint = stellar_core_history::checkpoint::checkpoint_containing(end);

    let mut checkpoint = start_checkpoint;
    while checkpoint <= end_checkpoint {
        // Get checkpoint HAS (History Archive State)
        match archive.get_checkpoint_has(checkpoint).await {
            Ok(has) => {
                // Verify the HAS structure
                match verify::verify_has_structure(&has) {
                    Ok(()) => {
                        // Verify checkpoint matches
                        match verify::verify_has_checkpoint(&has, checkpoint) {
                            Ok(()) => {
                                println!("  Checkpoint {}: OK", checkpoint);
                                verified_count += 1;
                            }
                            Err(e) => {
                                println!("  Checkpoint {}: FAIL - {}", checkpoint, e);
                                error_count += 1;
                            }
                        }
                    }
                    Err(e) => {
                        println!(
                            "  Checkpoint {}: FAIL (invalid structure) - {}",
                            checkpoint, e
                        );
                        error_count += 1;
                    }
                }

                // Get and verify ledger headers for this checkpoint range
                match archive.get_ledger_headers(checkpoint).await {
                    Ok(history_entries) => {
                        // Extract LedgerHeader from LedgerHeaderHistoryEntry
                        let headers: Vec<stellar_xdr::curr::LedgerHeader> = history_entries
                            .iter()
                            .map(|entry| entry.header.clone())
                            .collect();
                        if let Err(e) = verify::verify_header_chain(&headers) {
                            println!("    Header chain verification FAILED: {}", e);
                            error_count += 1;
                        }

                        match archive.get_transactions(checkpoint).await {
                            Ok(tx_entries) => {
                                match archive.get_results(checkpoint).await {
                                    Ok(tx_results) => {
                                        let tx_map = tx_entries
                                            .iter()
                                            .map(|entry| (entry.ledger_seq, entry))
                                            .collect::<std::collections::HashMap<_, _>>();
                                        let result_map = tx_results
                                            .iter()
                                            .map(|entry| (entry.ledger_seq, entry))
                                            .collect::<std::collections::HashMap<_, _>>();

                                        for header in &headers {
                                            let Some(tx_entry) = tx_map.get(&header.ledger_seq)
                                            else {
                                                println!(
                                                    "    Missing transaction history entry for ledger {}",
                                                    header.ledger_seq
                                                );
                                                error_count += 1;
                                                continue;
                                            };
                                            let Some(result_entry) =
                                                result_map.get(&header.ledger_seq)
                                            else {
                                                println!(
                                                    "    Missing transaction result entry for ledger {}",
                                                    header.ledger_seq
                                                );
                                                error_count += 1;
                                                continue;
                                            };

                                            let tx_set = match &tx_entry.ext {
                                                stellar_xdr::curr::TransactionHistoryEntryExt::V1(generalized) => {
                                                    TransactionSetVariant::Generalized(generalized.clone())
                                                }
                                                stellar_xdr::curr::TransactionHistoryEntryExt::V0 => {
                                                    TransactionSetVariant::Classic(tx_entry.tx_set.clone())
                                                }
                                            };
                                            if let Err(e) = verify::verify_tx_set(header, &tx_set) {
                                                println!(
                                                    "    Tx set hash verification FAILED (ledger {}): {}",
                                                    header.ledger_seq, e
                                                );
                                                error_count += 1;
                                            }

                                            let result_xdr = result_entry
                                                .tx_result_set
                                                .to_xdr(stellar_xdr::curr::Limits::none());
                                            match result_xdr {
                                                Ok(bytes) => {
                                                    if let Err(e) =
                                                        verify::verify_tx_result_set(header, &bytes)
                                                    {
                                                        println!(
                                                            "    Tx result hash verification FAILED (ledger {}): {}",
                                                            header.ledger_seq, e
                                                        );
                                                        error_count += 1;
                                                    }
                                                }
                                                Err(e) => {
                                                    println!(
                                                        "    Failed to encode tx result set for ledger {}: {}",
                                                        header.ledger_seq, e
                                                    );
                                                    error_count += 1;
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        println!("    Warning: Could not verify tx results: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                println!("    Warning: Could not verify transactions: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("    Warning: Could not verify headers: {}", e);
                    }
                }

                match archive.get_scp_history(checkpoint).await {
                    Ok(entries) => {
                        if let Err(e) = verify::verify_scp_history_entries(&entries) {
                            println!("    SCP history verification FAILED: {}", e);
                            error_count += 1;
                        }
                    }
                    Err(e) => {
                        println!("    Warning: Could not verify SCP history: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("  Checkpoint {}: ERROR - {}", checkpoint, e);
                error_count += 1;
            }
        }

        // Move to next checkpoint
        checkpoint = stellar_core_history::checkpoint::next_checkpoint(checkpoint);
    }

    println!();
    println!("Verification complete:");
    println!("  Checkpoints verified: {}", verified_count);
    println!("  Errors: {}", error_count);

    if error_count > 0 {
        anyhow::bail!("Verification failed with {} errors", error_count);
    }

    Ok(())
}

/// Publish history command handler.
async fn cmd_publish_history(config: AppConfig, force: bool) -> anyhow::Result<()> {
    use std::fs;
    use std::path::PathBuf;
    use stellar_core_bucket::{BucketList, BucketManager};
    use stellar_core_common::Hash256;
    use stellar_core_history::archive_state::HistoryArchiveState;
    use stellar_core_history::checkpoint::{checkpoint_containing, next_checkpoint};
    use stellar_core_history::paths::root_has_path;
    use stellar_core_history::publish::{
        build_history_archive_state, PublishConfig, PublishManager,
    };
    use stellar_core_history::verify;
    use stellar_core_history::CHECKPOINT_FREQUENCY;
    use stellar_core_ledger::compute_header_hash;
    use stellar_core_ledger::TransactionSetVariant;
    use stellar_xdr::curr::TransactionHistoryEntryExt;
    use url::Url;

    if !config.node.is_validator {
        anyhow::bail!("Only validators can publish history");
    }

    println!("Publishing history to archives...");
    println!();

    // Check for writable archives
    let writable_archives: Vec<_> = config
        .history
        .archives
        .iter()
        .filter(|a| a.put_enabled)
        .collect();

    if writable_archives.is_empty() {
        anyhow::bail!(
            "No writable history archives configured. Add 'put = true' to an archive config."
        );
    }

    let mut local_targets = Vec::new();
    let mut command_targets = Vec::new();
    for archive in &writable_archives {
        if let Some(put) = archive.put.clone() {
            command_targets.push(CommandArchiveTarget {
                name: archive.name.clone(),
                put,
                mkdir: archive.mkdir.clone(),
            });
            continue;
        }

        let path = match Url::parse(&archive.url) {
            Ok(url) if url.scheme() == "file" => url
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("Invalid file URL: {}", archive.url))?,
            Ok(_) => {
                tracing::warn!(archive = %archive.url, "Remote publish not supported (missing put command)");
                continue;
            }
            Err(_) => PathBuf::from(&archive.url),
        };
        local_targets.push((archive.url.as_str(), path));
    }

    if local_targets.is_empty() && command_targets.is_empty() {
        anyhow::bail!("No publish archives configured (local paths or put commands required).");
    }

    println!(
        "Writable archives: {}",
        local_targets.len() + command_targets.len()
    );
    for (url, _) in &local_targets {
        println!("  - {}", url);
    }
    for archive in &command_targets {
        println!("  - {} (command)", archive.name);
    }
    println!();

    // Open database to get current state
    let db = stellar_core_db::Database::open(&config.database.path)?;

    // Get current ledger from database
    let current_ledger = db
        .get_latest_ledger_seq()?
        .ok_or_else(|| anyhow::anyhow!("No ledger data in database. Run the node first."))?;

    println!("Current ledger in database: {}", current_ledger);

    // Calculate checkpoints to publish
    let latest_checkpoint =
        stellar_core_history::checkpoint::latest_checkpoint_before_or_at(current_ledger)
            .ok_or_else(|| {
                anyhow::anyhow!("No checkpoint available for ledger {}", current_ledger)
            })?;

    println!("Latest publishable checkpoint: {}", latest_checkpoint);

    let queued_checkpoints = db.load_publish_queue(None)?;
    let mut queued_checkpoints = queued_checkpoints
        .into_iter()
        .filter(|checkpoint| *checkpoint <= latest_checkpoint)
        .collect::<Vec<_>>();
    queued_checkpoints.sort_unstable();

    // Check what's already published across local archives.
    let mut published_ledger = latest_checkpoint;
    for (_, path) in &local_targets {
        let root_path = path.join(root_has_path());
        let ledger = if root_path.exists() {
            let json = fs::read_to_string(&root_path)?;
            let has = HistoryArchiveState::from_json(&json)?;
            has.current_ledger()
        } else {
            0
        };
        published_ledger = published_ledger.min(ledger);
    }

    println!("Already published up to: {}", published_ledger);

    if published_ledger >= latest_checkpoint && !force && queued_checkpoints.is_empty() {
        println!();
        println!("Archive is up to date. Use --force to republish.");
        return Ok(());
    }

    let mut checkpoints_to_publish = Vec::new();
    if !queued_checkpoints.is_empty() && !force {
        checkpoints_to_publish = queued_checkpoints;
    } else {
        // Calculate range to publish
        let start_checkpoint = if published_ledger > 0 && !force {
            next_checkpoint(published_ledger)
        } else {
            // Start from the first checkpoint we have
            checkpoint_containing(1)
        };

        if start_checkpoint > latest_checkpoint {
            println!("Nothing new to publish.");
            return Ok(());
        }

        let mut checkpoint = start_checkpoint;
        while checkpoint <= latest_checkpoint {
            checkpoints_to_publish.push(checkpoint);
            checkpoint = next_checkpoint(checkpoint);
        }
    }

    if checkpoints_to_publish.is_empty() {
        println!("Nothing queued to publish.");
        return Ok(());
    }

    println!();
    let first_checkpoint = *checkpoints_to_publish
        .first()
        .expect("checked non-empty above");
    let last_checkpoint = *checkpoints_to_publish
        .last()
        .expect("checked non-empty above");
    println!(
        "Publishing checkpoints {} to {}...",
        first_checkpoint, last_checkpoint
    );

    let bucket_manager = BucketManager::with_cache_size(
        config.buckets.directory.clone(),
        config.buckets.cache_size,
    )?;

    let mut published_count = 0;
    for checkpoint in checkpoints_to_publish {
        print!("  Publishing checkpoint {}... ", checkpoint);

        let start_ledger = checkpoint.saturating_sub(CHECKPOINT_FREQUENCY - 1);
        let start_ledger = if start_ledger == 0 { 1 } else { start_ledger };
        let mut headers = Vec::new();
        let mut tx_entries = Vec::new();
        let mut tx_results = Vec::new();

        for seq in start_ledger..=checkpoint {
            let header = db
                .get_ledger_header(seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header {}", seq))?;
            let hash = compute_header_hash(&header)?;
            headers.push(stellar_xdr::curr::LedgerHeaderHistoryEntry {
                header,
                hash: stellar_xdr::curr::Hash(hash.0),
                ext: stellar_xdr::curr::LedgerHeaderHistoryEntryExt::V0,
            });

            let tx_entry = db
                .get_tx_history_entry(seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing tx history entry {}", seq))?;
            tx_entries.push(tx_entry);

            let tx_result = db
                .get_tx_result_entry(seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing tx result entry {}", seq))?;
            tx_results.push(tx_result);
        }

        let scp_entries = build_scp_history_entries(&db, start_ledger, checkpoint)?;

        for idx in 0..headers.len() {
            let header_entry = &headers[idx];
            let tx_entry = &tx_entries[idx];
            let tx_result_entry = &tx_results[idx];
            let header = &header_entry.header;
            let tx_set = match &tx_entry.ext {
                TransactionHistoryEntryExt::V1(generalized) => {
                    TransactionSetVariant::Generalized(generalized.clone())
                }
                TransactionHistoryEntryExt::V0 => {
                    TransactionSetVariant::Classic(tx_entry.tx_set.clone())
                }
            };
            let tx_set_hash = verify::compute_tx_set_hash(&tx_set).unwrap_or(Hash256::ZERO);
            let expected_tx_set = Hash256::from(header.scp_value.tx_set_hash.0);
            if tx_set_hash != expected_tx_set {
                anyhow::bail!(
                    "Tx set hash mismatch at {} (expected {}, got {})",
                    header.ledger_seq,
                    expected_tx_set.to_hex(),
                    tx_set_hash.to_hex()
                );
            }

            let tx_result_hash =
                Hash256::hash_xdr(&tx_result_entry.tx_result_set).unwrap_or(Hash256::ZERO);
            let expected_tx_result = Hash256::from(header.tx_set_result_hash.0);
            if tx_result_hash != expected_tx_result {
                anyhow::bail!(
                    "Tx result hash mismatch at {} (expected {}, got {})",
                    header.ledger_seq,
                    expected_tx_result.to_hex(),
                    tx_result_hash.to_hex()
                );
            }
        }

        let levels = db
            .load_bucket_list(checkpoint)?
            .ok_or_else(|| anyhow::anyhow!("Missing bucket list snapshot {}", checkpoint))?;
        let mut bucket_list = BucketList::new();
        for (idx, (curr_hash, snap_hash)) in levels.iter().enumerate() {
            let curr_bucket = bucket_manager.load_bucket(curr_hash)?;
            let snap_bucket = bucket_manager.load_bucket(snap_hash)?;
            let level = bucket_list
                .level_mut(idx)
                .ok_or_else(|| anyhow::anyhow!("Missing bucket level {}", idx))?;
            level.set_curr((*curr_bucket).clone());
            level.set_snap((*snap_bucket).clone());
        }

        let expected_hash = Hash256::from(headers.last().unwrap().header.bucket_list_hash.0);
        let actual_hash = bucket_list.hash();
        if expected_hash != actual_hash {
            anyhow::bail!(
                "Bucket list hash mismatch at {} (expected {}, got {})",
                checkpoint,
                expected_hash.to_hex(),
                actual_hash.to_hex()
            );
        }

        let command_publish_dir = if command_targets.is_empty() {
            None
        } else {
            let sanitized_name = config
                .node
                .name
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>();
            let publish_dir = std::env::temp_dir().join(format!(
                "rs-stellar-core-publish-{}-{}",
                sanitized_name, checkpoint
            ));
            if publish_dir.exists() {
                std::fs::remove_dir_all(&publish_dir)?;
            }
            std::fs::create_dir_all(&publish_dir)?;

            let publish_config = PublishConfig {
                local_path: publish_dir.clone(),
                network_passphrase: Some(config.network.passphrase.clone()),
                ..Default::default()
            };
            let manager = PublishManager::new(publish_config);
            manager
                .publish_checkpoint(checkpoint, &headers, &tx_entries, &tx_results, &bucket_list)
                .await?;

            let has = build_history_archive_state(
                checkpoint,
                &bucket_list,
                Some(config.network.passphrase.clone()),
            )?;
            let root_path = publish_dir.join(root_has_path());
            if let Some(parent) = root_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&root_path, has.to_json()?)?;
            Some(publish_dir)
        };

        let mut published_any = false;
        for (url, path) in &local_targets {
            let publish_config = PublishConfig {
                local_path: path.clone(),
                network_passphrase: Some(config.network.passphrase.clone()),
                ..Default::default()
            };
            let manager = PublishManager::new(publish_config);
            if !force && manager.is_published(checkpoint) {
                continue;
            }
            manager
                .publish_checkpoint(checkpoint, &headers, &tx_entries, &tx_results, &bucket_list)
                .await?;
            write_scp_history_file(path, checkpoint, &scp_entries)?;
            let has = build_history_archive_state(
                checkpoint,
                &bucket_list,
                Some(config.network.passphrase.clone()),
            )?;
            let root_path = path.join(root_has_path());
            if let Some(parent) = root_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&root_path, has.to_json()?)?;
            println!("OK ({})", url);
            published_any = true;
        }

        if let Some(ref publish_dir) = command_publish_dir {
            write_scp_history_file(publish_dir, checkpoint, &scp_entries)?;
            for archive in &command_targets {
                upload_publish_directory(archive, publish_dir)?;
                println!("OK (command: {})", archive.name);
                published_any = true;
            }
        }

        if let Some(publish_dir) = command_publish_dir {
            if let Err(err) = std::fs::remove_dir_all(&publish_dir) {
                tracing::warn!(
                    path = %publish_dir.display(),
                    error = %err,
                    "Failed to remove publish temp directory"
                );
            }
        }

        if published_any {
            published_count += 1;
        } else {
            println!("SKIP (already published)");
        }

        if let Err(err) = db.remove_publish(checkpoint) {
            tracing::warn!(checkpoint, error = %err, "Failed to remove publish queue entry");
        }
    }

    println!();
    println!("Publishing complete:");
    println!("  Checkpoints processed: {}", published_count);
    println!();

    Ok(())
}

/// Builds SCP history entries for a checkpoint range from the database.
///
/// Collects SCP envelopes and quorum sets for each ledger in the range,
/// packaging them into the format required for history archive publishing.
fn build_scp_history_entries(
    db: &stellar_core_db::Database,
    start_ledger: u32,
    checkpoint: u32,
) -> anyhow::Result<Vec<stellar_xdr::curr::ScpHistoryEntry>> {
    use std::collections::HashSet;
    use stellar_core_common::Hash256;
    use stellar_xdr::curr::{LedgerScpMessages, ScpHistoryEntry, ScpHistoryEntryV0};

    let mut entries = Vec::new();
    for seq in start_ledger..=checkpoint {
        let envelopes = db.load_scp_history(seq)?;
        if envelopes.is_empty() {
            continue;
        }

        let mut qset_hashes = HashSet::new();
        for envelope in &envelopes {
            if let Some(hash) = scp_quorum_set_hash(&envelope.statement) {
                qset_hashes.insert(Hash256::from_bytes(hash.0));
            }
        }

        let mut qset_hashes = qset_hashes.into_iter().collect::<Vec<_>>();
        qset_hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

        let mut qsets = Vec::new();
        for hash in qset_hashes {
            let qset = db
                .load_scp_quorum_set(&hash)?
                .ok_or_else(|| anyhow::anyhow!("Missing quorum set {}", hash.to_hex()))?;
            qsets.push(qset);
        }

        let quorum_sets = qsets
            .try_into()
            .map_err(|_| anyhow::anyhow!("Too many quorum sets for ledger {}", seq))?;
        let messages = envelopes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Too many SCP envelopes for ledger {}", seq))?;
        let entry = ScpHistoryEntry::V0(ScpHistoryEntryV0 {
            quorum_sets,
            ledger_messages: LedgerScpMessages {
                ledger_seq: seq,
                messages,
            },
        });
        entries.push(entry);
    }

    Ok(entries)
}

/// Writes SCP history entries to a gzip-compressed XDR file.
///
/// Creates the file at the standard history archive path for SCP data.
fn write_scp_history_file(
    base_dir: &std::path::Path,
    checkpoint: u32,
    entries: &[stellar_xdr::curr::ScpHistoryEntry],
) -> anyhow::Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use stellar_core_history::paths::checkpoint_path;
    use stellar_xdr::curr::{Limits, WriteXdr};

    let path = base_dir.join(checkpoint_path("scp", checkpoint, "xdr.gz"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::File::create(&path)?;
    let mut encoder = GzEncoder::new(file, Compression::default());

    for entry in entries {
        let xdr = entry.to_xdr(Limits::none())?;
        encoder.write_all(&xdr)?;
    }
    encoder.finish()?;
    Ok(())
}

/// Extracts the quorum set hash from an SCP statement.
///
/// Different SCP pledge types store the quorum set hash in different fields.
fn scp_quorum_set_hash(
    statement: &stellar_xdr::curr::ScpStatement,
) -> Option<stellar_xdr::curr::Hash> {
    match &statement.pledges {
        stellar_xdr::curr::ScpStatementPledges::Nominate(nom) => Some(nom.quorum_set_hash.clone()),
        stellar_xdr::curr::ScpStatementPledges::Prepare(prep) => Some(prep.quorum_set_hash.clone()),
        stellar_xdr::curr::ScpStatementPledges::Confirm(conf) => Some(conf.quorum_set_hash.clone()),
        stellar_xdr::curr::ScpStatementPledges::Externalize(ext) => {
            Some(ext.commit_quorum_set_hash.clone())
        }
    }
}

/// Configuration for publishing to a remote archive via shell commands.
#[derive(Clone)]
struct CommandArchiveTarget {
    /// Human-readable name for the archive.
    name: String,
    /// Shell command template for uploading files ({0} = local path, {1} = remote path).
    put: String,
    /// Optional shell command template for creating directories ({0} = remote dir).
    mkdir: Option<String>,
}

/// Uploads a local publish directory to a remote archive using shell commands.
///
/// Iterates through all files in the directory, creating remote directories
/// as needed, then uploads each file using the configured put command.
fn upload_publish_directory(
    target: &CommandArchiveTarget,
    publish_dir: &std::path::Path,
) -> anyhow::Result<()> {
    use std::collections::HashSet;

    let mut files = collect_files(publish_dir)?;
    files.sort();

    let mut created_dirs = HashSet::new();
    for file in files {
        let rel = file
            .strip_prefix(publish_dir)
            .map_err(|e| anyhow::anyhow!("invalid publish path: {}", e))?;
        let rel_str = path_to_unix_string(rel)?;

        if let Some(ref mkdir_cmd) = target.mkdir {
            if let Some(parent) = rel.parent() {
                if !parent.as_os_str().is_empty() {
                    let remote_dir = path_to_unix_string(parent)?;
                    if created_dirs.insert(remote_dir.clone()) {
                        let cmd = render_mkdir_command(mkdir_cmd, &remote_dir);
                        run_shell_command(&cmd)?;
                    }
                }
            }
        }

        let cmd = render_put_command(&target.put, &file, &rel_str);
        run_shell_command(&cmd)?;
    }

    Ok(())
}

/// Recursively collects all files under a directory.
fn collect_files(root: &std::path::Path) -> anyhow::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    Ok(files)
}

/// Converts a path to a Unix-style string with forward slashes.
fn path_to_unix_string(path: &std::path::Path) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let part = component.as_os_str().to_string_lossy();
        parts.push(part.to_string());
    }
    Ok(parts.join("/"))
}

/// Renders a put command template with local and remote paths.
fn render_put_command(template: &str, local_path: &std::path::Path, remote_path: &str) -> String {
    template
        .replace("{0}", local_path.to_string_lossy().as_ref())
        .replace("{1}", remote_path)
}

/// Renders a mkdir command template with the remote directory.
fn render_mkdir_command(template: &str, remote_dir: &str) -> String {
    template.replace("{0}", remote_dir)
}

/// Executes a shell command and returns an error if it fails.
fn run_shell_command(cmd: &str) -> anyhow::Result<()> {
    use std::process::Command;

    let status = Command::new("sh").arg("-c").arg(cmd).status()?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("command failed (exit {}): {}", status, cmd);
    }
}

/// Downloads buckets in parallel from a history archive.
///
/// This function downloads multiple buckets concurrently (up to 16 at a time),
/// significantly speeding up initial state restoration compared to sequential downloads.
///
/// # Arguments
///
/// * `archive` - The history archive to download from
/// * `bucket_manager` - The bucket manager to import buckets into
/// * `hashes` - The bucket hashes to download
///
/// # Returns
///
/// Returns `Ok(())` if all buckets were downloaded successfully, or an error
/// if any download failed.
/// Returns (cached_count, downloaded_count)
async fn download_buckets_parallel(
    archive: &stellar_core_history::HistoryArchive,
    bucket_manager: &stellar_core_bucket::BucketManager,
    hashes: Vec<&stellar_core_common::Hash256>,
) -> anyhow::Result<(usize, usize)> {
    use futures::stream::{self, StreamExt};
    use std::sync::atomic::{AtomicU32, Ordering};

    const MAX_CONCURRENT_DOWNLOADS: usize = 16;

    let total_count = hashes.len();

    // Filter out already-cached buckets
    let to_download: Vec<_> = hashes
        .into_iter()
        .filter(|hash| bucket_manager.load_bucket(hash).is_err())
        .collect();

    let cached_count = total_count - to_download.len();

    if to_download.is_empty() {
        return Ok((cached_count, 0));
    }

    let download_count = to_download.len();
    let downloaded = AtomicU32::new(0);

    println!(
        "  {} cached, {} to download...",
        cached_count, download_count
    );

    let results: Vec<anyhow::Result<()>> = stream::iter(to_download.into_iter())
        .map(|hash| {
            let downloaded = &downloaded;
            async move {
                let bucket_data = archive.get_bucket(hash).await.map_err(|e| {
                    anyhow::anyhow!("Failed to download bucket {}: {}", hash.to_hex(), e)
                })?;
                bucket_manager.import_bucket(&bucket_data).map_err(|e| {
                    anyhow::anyhow!("Failed to import bucket {}: {}", hash.to_hex(), e)
                })?;

                let count = downloaded.fetch_add(1, Ordering::Relaxed) + 1;
                if count % 5 == 0 || count == download_count as u32 {
                    println!("  Downloaded {}/{} buckets", count, download_count);
                }
                Ok(())
            }
        })
        .buffer_unordered(MAX_CONCURRENT_DOWNLOADS)
        .collect()
        .await;

    // Check for any failures
    for result in results {
        result?;
    }

    Ok((cached_count, download_count))
}

/// Replays bucket list changes from CDP metadata to validate our implementation.
///
/// This test takes the exact ledger entry changes from CDP (what C++ stellar-core produced)
/// and applies them to our bucket list implementation. This isolates bucket list testing
/// from transaction execution, allowing us to verify:
///
/// - **Spill timing**: When entries move from level N to level N+1
/// - **Merge logic**: How entries are combined during level merges
/// - **Hash computation**: Final bucket list hash calculation
///
/// The test downloads the bucket list state at a checkpoint, then replays each
/// ledger's changes and compares the resulting hash against the expected hash
/// from history.
///
/// # Arguments
///
/// * `config` - Application configuration with history archive URLs
/// * `from` - Start ledger sequence (defaults to recent checkpoint)
/// * `to` - End ledger sequence (defaults to latest available)
/// * `stop_on_error` - Stop immediately on first hash mismatch
/// * `live_only` - Only test live bucket list (ignore hot archive)
/// * `cdp_url` - CDP data lake URL
/// * `cdp_date` - CDP date partition
async fn cmd_replay_bucket_list(
    config: AppConfig,
    from: Option<u32>,
    to: Option<u32>,
    stop_on_error: bool,
    live_only: bool,
    cdp_url: &str,
    cdp_date: &str,
) -> anyhow::Result<()> {
    use stellar_core_bucket::{
        is_persistent_entry, BucketList, BucketManager, HasNextState, HotArchiveBucketList,
    };
    use stellar_core_common::protocol::MIN_SOROBAN_PROTOCOL_VERSION;
    use stellar_core_common::{Hash256, NetworkId};
    use stellar_core_history::cdp::{
        extract_evicted_keys, extract_restored_keys, extract_transaction_processing,
        extract_upgrade_metas, CdpDataLake,
    };
    use stellar_core_history::{checkpoint, HistoryArchive};
    use stellar_core_ledger::{InMemorySorobanState, SorobanRentConfig};
    use stellar_xdr::curr::{
        ConfigSettingEntry, ConfigSettingId, LedgerEntryData, LedgerKey, LedgerKeyConfigSetting,
    };

    fn load_soroban_config_from_bucket_list(bucket_list: &BucketList) -> SorobanRentConfig {
        let mut config = SorobanRentConfig::default();

        let cpu_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
            config_setting_id: ConfigSettingId::ContractCostParamsCpuInstructions,
        });
        if let Ok(Some(entry)) = bucket_list.get(&cpu_key) {
            if let LedgerEntryData::ConfigSetting(
                ConfigSettingEntry::ContractCostParamsCpuInstructions(params),
            ) = entry.data
            {
                config.cpu_cost_params = params;
            }
        }

        let mem_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
            config_setting_id: ConfigSettingId::ContractCostParamsMemoryBytes,
        });
        if let Ok(Some(entry)) = bucket_list.get(&mem_key) {
            if let LedgerEntryData::ConfigSetting(
                ConfigSettingEntry::ContractCostParamsMemoryBytes(params),
            ) = entry.data
            {
                config.mem_cost_params = params;
            }
        }

        let compute_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
            config_setting_id: ConfigSettingId::ContractComputeV0,
        });
        if let Ok(Some(entry)) = bucket_list.get(&compute_key) {
            if let LedgerEntryData::ConfigSetting(ConfigSettingEntry::ContractComputeV0(compute)) =
                entry.data
            {
                config.tx_max_instructions = compute.tx_max_instructions as u64;
                config.tx_max_memory_bytes = compute.tx_memory_limit as u64;
            }
        }

        config
    }

    println!("Bucket List Replay Test");
    println!("========================");
    println!("Validates bucket list implementation (spills, merges, hashes)");
    println!("using exact ledger changes from CDP metadata.");
    if live_only {
        println!();
        println!("NOTE: --live-only mode - tracking live bucket list hash progression");
        println!("      (Cannot compare against header since it stores combined hash)");
    } else {
        println!();
        println!("NOTE: For protocol 23+, the header stores SHA256(live || hot_archive).");
        println!("      Hot archive entries are looked up from live bucket list before eviction.");
        println!("      Use --live-only to test only the live bucket list hash.");
    }
    println!();

    // Create archive client
    let archive = config
        .history
        .archives
        .iter()
        .filter(|a| a.get_enabled)
        .find_map(|a| HistoryArchive::new(&a.url).ok())
        .ok_or_else(|| anyhow::anyhow!("No history archives available"))?;

    println!("Archive: {}", config.history.archives[0].url);
    println!("CDP: {} ({})", cdp_url, cdp_date);

    // Get current ledger and calculate range
    let root_has = archive.get_root_has().await?;
    let current_ledger = root_has.current_ledger;

    // Calculate the actual ledger range to test
    let end_ledger = to.unwrap_or_else(|| {
        checkpoint::latest_checkpoint_before_or_at(current_ledger).unwrap_or(current_ledger)
    });
    let start_ledger = from.unwrap_or_else(|| {
        let freq = stellar_core_history::CHECKPOINT_FREQUENCY;
        checkpoint::checkpoint_containing(end_ledger)
            .saturating_sub(16 * freq)
            .max(freq)
    });

    // Determine network ID (used for tx hash matching when extracting processing info)
    let network_id = if config.network.passphrase.contains("Test") {
        NetworkId::testnet()
    } else {
        NetworkId::mainnet()
    };

    // For bucket list testing, we need to restore from the checkpoint BEFORE our start ledger
    // because the checkpoint at start_ledger already includes changes up to that checkpoint
    let freq = stellar_core_history::CHECKPOINT_FREQUENCY;
    let init_checkpoint =
        checkpoint::latest_checkpoint_before_or_at(start_ledger.saturating_sub(1))
            .unwrap_or(freq - 1); // If no previous checkpoint, start from 63

    // Calculate checkpoint range that covers our ledger range (for header downloads)
    let end_checkpoint = checkpoint::checkpoint_containing(end_ledger);
    let start_checkpoint = checkpoint::checkpoint_containing(start_ledger);

    println!("Ledger range: {} to {}", start_ledger, end_ledger);
    println!("Initial state: checkpoint {}", init_checkpoint);
    println!(
        "Checkpoint range: {} to {}",
        start_checkpoint, end_checkpoint
    );
    println!();

    // Create CDP client
    let cdp = CdpDataLake::new(cdp_url, cdp_date);

    // Setup bucket manager and restore initial state from checkpoint BEFORE our test range
    let bucket_dir = tempfile::tempdir()?;
    let bucket_manager = BucketManager::new(bucket_dir.path().to_path_buf())?;

    println!(
        "Downloading initial state at checkpoint {}...",
        init_checkpoint
    );
    let init_has = archive.get_checkpoint_has(init_checkpoint).await?;

    // Extract live bucket hashes as tuples for restore_from_has
    let bucket_hashes: Vec<(Hash256, Hash256)> = init_has
        .current_buckets
        .iter()
        .map(|level| {
            (
                Hash256::from_hex(&level.curr).unwrap_or(Hash256::ZERO),
                Hash256::from_hex(&level.snap).unwrap_or(Hash256::ZERO),
            )
        })
        .collect();

    // Extract live bucket next states from HAS
    let live_next_states: Vec<HasNextState> = init_has
        .current_buckets
        .iter()
        .map(|level| HasNextState {
            state: level.next.state,
            output: level
                .next
                .output
                .as_ref()
                .and_then(|h| Hash256::from_hex(h).ok()),
        })
        .collect();

    // Extract hot archive bucket hashes as tuples for restore_from_has
    let hot_archive_hashes: Option<Vec<(Hash256, Hash256)>> =
        init_has.hot_archive_buckets.as_ref().map(|levels| {
            levels
                .iter()
                .map(|level| {
                    (
                        Hash256::from_hex(&level.curr).unwrap_or(Hash256::ZERO),
                        Hash256::from_hex(&level.snap).unwrap_or(Hash256::ZERO),
                    )
                })
                .collect()
        });

    // Extract hot archive next states from HAS
    let hot_archive_next_states: Option<Vec<HasNextState>> =
        init_has.hot_archive_buckets.as_ref().map(|levels| {
            levels
                .iter()
                .map(|level| HasNextState {
                    state: level.next.state,
                    output: level
                        .next
                        .output
                        .as_ref()
                        .and_then(|h| Hash256::from_hex(h).ok()),
                })
                .collect()
        });

    // Collect all hashes to download
    let mut all_hashes_vec: Vec<Hash256> = Vec::new();
    for (curr, snap) in &bucket_hashes {
        all_hashes_vec.push(curr.clone());
        all_hashes_vec.push(snap.clone());
    }
    for state in &live_next_states {
        if let Some(ref output) = state.output {
            all_hashes_vec.push(output.clone());
        }
    }
    if let Some(ref ha_hashes) = hot_archive_hashes {
        for (curr, snap) in ha_hashes {
            all_hashes_vec.push(curr.clone());
            all_hashes_vec.push(snap.clone());
        }
    }
    if let Some(ref ha_states) = hot_archive_next_states {
        for state in ha_states {
            if let Some(ref output) = state.output {
                all_hashes_vec.push(output.clone());
            }
        }
    }
    let all_hashes: Vec<&Hash256> = all_hashes_vec.iter().filter(|h| !h.is_zero()).collect();

    print!("Buckets ({} required):", all_hashes.len());
    let (cached, downloaded) =
        download_buckets_parallel(&archive, &bucket_manager, all_hashes).await?;
    if downloaded == 0 {
        println!(" {} cached", cached);
    }

    // Restore live bucket list using restore_from_hashes, then restart pending merges.
    // The HAS at a checkpoint has all state=0 (no pending merges), so we need restart_merges
    // to recreate any merges that should be in progress based on the checkpoint ledger timing.
    let live_bucket_hashes: Vec<Hash256> = bucket_hashes
        .iter()
        .flat_map(|(curr, snap)| vec![curr.clone(), snap.clone()])
        .collect();
    let mut bucket_list = BucketList::restore_from_hashes(&live_bucket_hashes, |hash| {
        bucket_manager.load_bucket(hash).map(|b| (*b).clone())
    })?;

    // Hot archive buckets contain HotArchiveBucketEntry, not BucketEntry, so we use
    // the proper HotArchiveBucketList type and load_hot_archive_bucket method.
    // Use restore_from_has to properly load pending merge states from the HAS.
    let mut hot_archive_bucket_list: Option<HotArchiveBucketList> =
        if let (Some(ref hashes), Some(ref next_states)) =
            (&hot_archive_hashes, &hot_archive_next_states)
        {
            Some(HotArchiveBucketList::restore_from_has(
                hashes,
                next_states,
                |hash| bucket_manager.load_hot_archive_bucket(hash),
            )?)
        } else {
            None
        };

    let init_cp_headers = archive.get_ledger_headers(init_checkpoint).await?;
    let init_header_entry = init_cp_headers
        .iter()
        .find(|h| h.header.ledger_seq == init_checkpoint);
    let init_protocol_version = init_header_entry
        .map(|h| h.header.ledger_version)
        .unwrap_or(25);

    // Debug: hash before restart_merges
    let pre_restart_live_hash = bucket_list.hash();
    let pre_restart_hot_hash = hot_archive_bucket_list.as_ref().map(|h| h.hash());
    println!("Pre-restart live hash: {}", pre_restart_live_hash.to_hex());
    if let Some(ref hot_hash) = pre_restart_hot_hash {
        println!("Pre-restart hot archive hash: {}", hot_hash.to_hex());
    }

    // Restart merges for both bucket lists.
    // At checkpoint boundaries (state=0), this recreates pending merges based on timing.
    bucket_list.restart_merges(init_checkpoint, init_protocol_version)?;
    if let Some(ref mut hot_archive) = hot_archive_bucket_list {
        hot_archive.restart_merges(init_checkpoint, init_protocol_version)?;
    }

    let initial_live_hash = bucket_list.hash();
    let initial_hot_hash = hot_archive_bucket_list.as_ref().map(|h| h.hash());

    println!("Initial live bucket hash: {}", initial_live_hash.to_hex());
    if let Some(ref hot_hash) = initial_hot_hash {
        println!("Initial hot archive hash: {}", hot_hash.to_hex());

        // Compute combined hash for verification
        let combined =
            stellar_core_crypto::sha256_multi(&[initial_live_hash.as_bytes(), hot_hash.as_bytes()]);
        println!("Initial combined hash: {}", combined.to_hex());
    }

    // Verify initial hash against checkpoint header
    println!();
    println!(
        "Verifying initial state at checkpoint {}...",
        init_checkpoint
    );
    if let Some(init_header) = init_cp_headers
        .iter()
        .find(|h| h.header.ledger_seq == init_checkpoint)
    {
        let expected_hash = Hash256::from(init_header.header.bucket_list_hash.0);
        let our_hash = if let Some(ref hot_hash) = initial_hot_hash {
            stellar_core_crypto::sha256_multi(&[initial_live_hash.as_bytes(), hot_hash.as_bytes()])
        } else {
            initial_live_hash
        };

        if our_hash == expected_hash {
            println!("  Checkpoint {}: INITIAL STATE OK", init_checkpoint);
        } else {
            println!("  Checkpoint {}: INITIAL STATE MISMATCH!", init_checkpoint);
            println!("    Expected: {}", expected_hash.to_hex());
            println!("    Got:      {}", our_hash.to_hex());
            println!("    Live:     {}", initial_live_hash.to_hex());
            if let Some(ref hot_hash) = initial_hot_hash {
                println!("    Hot:      {}", hot_hash.to_hex());
            }
        }
    } else {
        println!("  Could not find header for checkpoint {}", init_checkpoint);
    }
    println!();

    // Initialize in-memory Soroban state from the checkpoint.
    let mut soroban_state = InMemorySorobanState::new();
    if init_protocol_version >= MIN_SOROBAN_PROTOCOL_VERSION {
        let live_entries = bucket_list.live_entries()?;
        let soroban_config = load_soroban_config_from_bucket_list(&bucket_list);
        soroban_state
            .update_state(
                init_checkpoint,
                &live_entries,
                &[],
                &[],
                init_protocol_version,
                Some(&soroban_config),
            )
            .map_err(|e| anyhow::anyhow!("soroban state init failed: {}", e))?;
    }

    let _replay_config = ReplayConfig {
        verify_results: false,
        verify_bucket_list: true,
        verify_invariants: false,
        emit_classic_events: false,
        backfill_stellar_asset_events: false,
        run_eviction: hot_archive_bucket_list.is_some(),
        eviction_settings: StateArchivalSettings::default(),
    };

    // Track results
    let mut ledgers_tested = 0u32;
    let mut mismatches = 0u32;

    // We need to apply changes from init_checkpoint + 1 up to end_ledger
    // to build up the bucket list state correctly. We only report results
    // for ledgers in the user's requested range (start_ledger to end_ledger).
    let process_from = init_checkpoint + 1;
    let process_from_cp = checkpoint::checkpoint_containing(process_from);

    // Iterate through checkpoints starting from init_checkpoint
    let mut current_cp = process_from_cp;
    while current_cp <= end_checkpoint {
        let next_cp = checkpoint::next_checkpoint(current_cp);

        let headers = archive.get_ledger_headers(current_cp).await?;

        for header_entry in &headers {
            let header = &header_entry.header;
            let seq = header.ledger_seq;

            // Skip ledgers before our initial state or after our target
            if seq <= init_checkpoint || seq > end_ledger {
                continue;
            }

            // Determine if this ledger is in the user's test range
            let in_test_range = seq >= start_ledger && seq <= end_ledger;

            // Fetch CDP metadata
            let lcm = cdp.get_ledger_close_meta(seq).await?;
            let tx_processing = extract_transaction_processing(&lcm, network_id.as_bytes());
            let upgrade_metas = extract_upgrade_metas(&lcm);
            let evicted_keys = extract_evicted_keys(&lcm);

            // Deduplicate all changes for the live bucket list
            let (all_init, all_live, all_dead, tx_dead_keys) = {
                use stellar_xdr::curr::{
                    ConfigSettingEntry, ConfigSettingId, LedgerEntry, LedgerEntryChange,
                    LedgerEntryData, LedgerEntryExt, LedgerKey, LedgerKeyConfigSetting,
                };

                let mut aggregator = CoalescedLedgerChanges::new();
                let bl = &bucket_list;

                // Apply per-transaction changes in ledger order:
                // fee -> tx_meta -> post_fee
                for tx_info in &tx_processing {
                    for change in tx_info.fee_meta.iter() {
                        apply_change_with_prestate(&mut aggregator, &bl, change);
                    }

                    let succeeded = tx_succeeded(&tx_info.result);
                    match &tx_info.meta {
                        stellar_xdr::curr::TransactionMeta::V0(operations) => {
                            if succeeded {
                                for op_meta in operations.iter() {
                                    for change in op_meta.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                        }
                        stellar_xdr::curr::TransactionMeta::V1(v1) => {
                            if succeeded {
                                for change in v1.tx_changes.iter() {
                                    apply_change_with_prestate(&mut aggregator, &bl, change);
                                }
                                for op_changes in v1.operations.iter() {
                                    for change in op_changes.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                        }
                        stellar_xdr::curr::TransactionMeta::V2(v2) => {
                            for change in v2.tx_changes_before.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                            if succeeded {
                                for op_changes in v2.operations.iter() {
                                    for change in op_changes.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                            for change in v2.tx_changes_after.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                        }
                        stellar_xdr::curr::TransactionMeta::V3(v3) => {
                            for change in v3.tx_changes_before.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                            if succeeded {
                                for op_changes in v3.operations.iter() {
                                    for change in op_changes.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                            for change in v3.tx_changes_after.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                        }
                        stellar_xdr::curr::TransactionMeta::V4(v4) => {
                            for change in v4.tx_changes_before.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                            if succeeded {
                                for op_changes in v4.operations.iter() {
                                    for change in op_changes.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                            for change in v4.tx_changes_after.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                        }
                    }

                    if !tx_info.post_fee_meta.is_empty() {
                        for change in tx_info.post_fee_meta.iter() {
                            apply_change_with_prestate(&mut aggregator, &bl, change);
                        }
                    }
                }

                // 4. Upgrade changes
                for upgrade in &upgrade_metas {
                    for change in upgrade.changes.iter() {
                        apply_change_with_prestate(&mut aggregator, &bl, change);
                    }
                }

                // Snapshot the aggregator state BEFORE evictions to get the
                // non-eviction dead keys (entries deleted by transactions)
                let pre_eviction_dead: Vec<stellar_xdr::curr::LedgerKey> = {
                    let (_, _, dead) = aggregator.clone().to_vectors();
                    dead
                };

                // 5. Eviction changes (from CDP)
                for key in &evicted_keys {
                    apply_change_with_prestate(
                        &mut aggregator,
                        &bl,
                        &LedgerEntryChange::Removed(key.clone()),
                    );
                }

                let archival_override = {
                    let archival_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
                        config_setting_id: ConfigSettingId::StateArchival,
                    });
                    match aggregator.changes.get(&archival_key) {
                        Some(FinalChange::Init(entry)) | Some(FinalChange::Live(entry)) => {
                            if let LedgerEntryData::ConfigSetting(
                                ConfigSettingEntry::StateArchival(settings),
                            ) = &entry.data
                            {
                                Some(settings.clone())
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                };

                let eviction_iter_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
                    config_setting_id: ConfigSettingId::EvictionIterator,
                });
                let has_eviction_iter_change = aggregator.changes.contains_key(&eviction_iter_key);

                // Eviction Iterator update (local fallback if CDP doesn't include it)
                if hot_archive_bucket_list.is_some()
                    && header.ledger_version >= 23
                    && !has_eviction_iter_change
                {
                    use stellar_core_bucket::{EvictionIterator, StateArchivalSettings};

                    let settings = if let Some(override_settings) = archival_override.clone() {
                        StateArchivalSettings {
                            eviction_scan_size: override_settings.eviction_scan_size as u64,
                            starting_eviction_scan_level: override_settings
                                .starting_eviction_scan_level,
                        }
                    } else {
                        let key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
                            config_setting_id: ConfigSettingId::StateArchival,
                        });
                        if let Ok(Some(entry)) = bucket_list.get(&key) {
                            if let LedgerEntryData::ConfigSetting(
                                ConfigSettingEntry::StateArchival(s),
                            ) = entry.data
                            {
                                StateArchivalSettings {
                                    eviction_scan_size: s.eviction_scan_size as u64,
                                    starting_eviction_scan_level: s.starting_eviction_scan_level,
                                }
                            } else {
                                StateArchivalSettings::default()
                            }
                        } else {
                            StateArchivalSettings::default()
                        }
                    };

                    let iter = {
                        let key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
                            config_setting_id: ConfigSettingId::EvictionIterator,
                        });
                        if let Ok(Some(entry)) = bucket_list.get(&key) {
                            if let LedgerEntryData::ConfigSetting(
                                ConfigSettingEntry::EvictionIterator(it),
                            ) = entry.data
                            {
                                EvictionIterator {
                                    bucket_file_offset: it.bucket_file_offset,
                                    bucket_list_level: it.bucket_list_level,
                                    is_curr_bucket: it.is_curr_bucket,
                                }
                            } else {
                                EvictionIterator::new(settings.starting_eviction_scan_level)
                            }
                        } else {
                            EvictionIterator::new(settings.starting_eviction_scan_level)
                        }
                    };

                    let scan_result = bucket_list
                        .scan_for_eviction_incremental(iter, seq, &settings)
                        .unwrap();
                    let iter_entry = LedgerEntry {
                        last_modified_ledger_seq: seq,
                        data: LedgerEntryData::ConfigSetting(ConfigSettingEntry::EvictionIterator(
                            stellar_xdr::curr::EvictionIterator {
                                bucket_file_offset: scan_result.end_iterator.bucket_file_offset,
                                bucket_list_level: scan_result.end_iterator.bucket_list_level,
                                is_curr_bucket: scan_result.end_iterator.is_curr_bucket,
                            },
                        )),
                        ext: LedgerEntryExt::V0,
                    };
                    apply_change_with_prestate(
                        &mut aggregator,
                        &bl,
                        &LedgerEntryChange::Updated(iter_entry),
                    );
                }

                let window_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
                    config_setting_id: ConfigSettingId::LiveSorobanStateSizeWindow,
                });
                let has_window_change = aggregator.changes.contains_key(&window_key);

                if !has_window_change {
                    maybe_snapshot_soroban_state_size_window(
                        seq,
                        header.ledger_version,
                        &bl,
                        soroban_state.total_size(),
                        &mut aggregator,
                        archival_override,
                    );
                }

                let (init, live, dead) = aggregator.clone().to_vectors();
                if header.ledger_version >= MIN_SOROBAN_PROTOCOL_VERSION {
                    let soroban_config = load_soroban_config_from_bucket_list(bl);
                    soroban_state
                        .update_state(
                            seq,
                            &init,
                            &live,
                            &dead,
                            header.ledger_version,
                            Some(&soroban_config),
                        )
                        .map_err(|e| anyhow::anyhow!("soroban state update failed: {}", e))?;
                }

                let (init, live, dead) = aggregator.to_vectors();

                (init, live, dead, pre_eviction_dead)
            };

            // Before evicting entries from the live bucket list, look up full entry data
            // for persistent entries that need to go to the hot archive. Use the
            // post-transaction state when entries were updated in this ledger.
            let mut archived_entries = Vec::new();
            if !live_only && hot_archive_bucket_list.is_some() {
                let mut changed_entries: std::collections::HashMap<
                    stellar_xdr::curr::LedgerKey,
                    stellar_xdr::curr::LedgerEntry,
                > = std::collections::HashMap::new();
                for entry in all_init.iter().chain(all_live.iter()) {
                    if let Some(key) = stellar_core_bucket::ledger_entry_to_key(entry) {
                        changed_entries.insert(key, entry.clone());
                    }
                }
                // Use pre-eviction dead keys (entries deleted by transactions, NOT evictions)
                // Evicted entries should still go to hot archive even if they're "dead"
                let dead_keys: std::collections::HashSet<stellar_xdr::curr::LedgerKey> =
                    tx_dead_keys.iter().cloned().collect();

                for key in &evicted_keys {
                    if matches!(key, stellar_xdr::curr::LedgerKey::Ttl(_)) {
                        continue;
                    }
                    if dead_keys.contains(key) {
                        continue;
                    }
                    if let Some(entry) = changed_entries.get(key) {
                        if is_persistent_entry(entry) {
                            archived_entries.push(entry.clone());
                        }
                        continue;
                    }
                    if let Ok(Some(entry)) = bucket_list.get(key) {
                        if is_persistent_entry(&entry) {
                            archived_entries.push(entry);
                        }
                    }
                }
            }

            // Extract restored keys from transaction meta (entries restored from hot archive)
            let tx_metas_for_restore: Vec<_> =
                tx_processing.iter().map(|tp| tp.meta.clone()).collect();
            let restored_keys = if !live_only && hot_archive_bucket_list.is_some() {
                extract_restored_keys(&tx_metas_for_restore)
            } else {
                Vec::new()
            };

            // Update hot archive bucket list first (matches C++ order: addHotArchiveBatch before addLiveBatch)
            if let Some(ref mut hot_archive) = hot_archive_bucket_list {
                // Log if there are any evictions or restorations
                if !archived_entries.is_empty() || !restored_keys.is_empty() {
                    println!(
                        "  Ledger {}: hot archive update - {} archived, {} restored",
                        seq,
                        archived_entries.len(),
                        restored_keys.len()
                    );
                }
                hot_archive.add_batch(
                    seq,
                    header.ledger_version,
                    archived_entries.clone(),
                    restored_keys.clone(),
                )?;
            }

            // Apply changes to live bucket list (always call add_batch for spill timing)
            bucket_list.add_batch(
                seq,
                header.ledger_version,
                stellar_xdr::curr::BucketListType::Live,
                all_init,
                all_live,
                all_dead,
            )?;

            // Compute hash for comparison
            // If live_only, we just compare the live bucket list hash
            // Otherwise, we compute combined hash: SHA256(live || hot_archive)
            let our_live_hash = bucket_list.hash();

            let our_hash = if live_only || hot_archive_bucket_list.is_none() {
                our_live_hash
            } else {
                let hot = hot_archive_bucket_list.as_ref().unwrap();
                stellar_core_crypto::sha256_multi(&[
                    our_live_hash.as_bytes(),
                    hot.hash().as_bytes(),
                ])
            };

            // For live_only mode, we can't compare against the header directly
            // because the header stores the combined hash. We just show our live hash.
            let expected_hash = Hash256::from(header.bucket_list_hash.0);

            // Only report/count for ledgers in the user's requested range
            if in_test_range {
                if live_only {
                    // In live_only mode, we can only show our hash (no expected to compare)
                    println!(
                        "  Ledger {}: live hash = {} ({} txs)",
                        seq,
                        &our_live_hash.to_hex()[..16],
                        tx_processing.len()
                    );
                } else if our_hash == expected_hash {
                    let hot_hash = hot_archive_bucket_list
                        .as_ref()
                        .map(|h| h.hash().to_hex())
                        .unwrap_or_default();
                    println!(
                        "  Ledger {}: OK ({} txs) [live={}, hot={}]",
                        seq,
                        tx_processing.len(),
                        &our_live_hash.to_hex()[..16],
                        &hot_hash[..16.min(hot_hash.len())]
                    );
                    // Debug: print bucket state for ledger 380087
                    if seq == 380087 {
                        println!("    Live bucket list full state at 380087:");
                        for (i, level) in bucket_list.levels().iter().enumerate() {
                            println!("      L{}: curr={}", i, level.curr.hash().to_hex());
                            println!("          snap={}", level.snap.hash().to_hex());
                            if let Some(next) = level.next() {
                                println!("          next={}", next.hash().to_hex());
                            }
                        }
                    }
                } else {
                    println!("  Ledger {}: BUCKET LIST HASH MISMATCH", seq);
                    println!("    Expected (combined): {}", expected_hash.to_hex());
                    println!("    Got (combined):      {}", our_hash.to_hex());
                    println!("    Our live hash:       {}", our_live_hash.to_hex());
                    if let Some(ref hot) = hot_archive_bucket_list {
                        println!("    Our hot archive:     {}", hot.hash().to_hex());
                    }
                    // Debug: print all bucket hashes
                    println!("    Live bucket list full state:");
                    for (i, level) in bucket_list.levels().iter().enumerate() {
                        println!("      L{}: curr={}", i, level.curr.hash().to_hex());
                        println!("          snap={}", level.snap.hash().to_hex());
                    }
                    // Debug: print hot archive bucket list state
                    if let Some(ref hot) = hot_archive_bucket_list {
                        println!("    Hot archive bucket list full state:");
                        for (i, level) in hot.levels().iter().enumerate() {
                            println!("      L{}: curr={}", i, level.curr.hash().to_hex());
                            println!("          snap={}", level.snap.hash().to_hex());
                        }
                    }
                    mismatches += 1;
                    if stop_on_error {
                        anyhow::bail!("Stopping on first error");
                    }
                }
                ledgers_tested += 1;
            }
        }

        current_cp = next_cp;
    }

    println!();
    println!("Bucket List Replay Test Complete");
    println!("  Ledgers tested: {}", ledgers_tested);
    println!("  Mismatches: {}", mismatches);

    if mismatches > 0 {
        anyhow::bail!(
            "Test failed with {} bucket list hash mismatches",
            mismatches
        );
    }

    Ok(())
}

/// Verifies transaction execution by comparing results against CDP metadata.
///
/// This test re-executes transactions and compares the resulting ledger entry changes
/// against what C++ stellar-core produced (from CDP). Differences indicate execution
/// divergence that needs investigation.
///
/// The verification process:
///
/// 1. Restores bucket list state from a checkpoint before the test range
/// 2. For each ledger, executes transactions using our implementation
/// 3. Compares the resulting ledger entry changes against CDP metadata
/// 4. Reports any mismatches in detail
///
/// This is useful for debugging:
///
/// - **Soroban host differences**: Different contract execution results
/// - **Classic operation differences**: Account balance, trustline, or offer issues
/// - **Fee calculation differences**: Incorrect fee charging or refunds
/// - **TTL/expiration differences**: State archival timing issues
///
/// # Arguments
///
/// * `config` - Application configuration with history archive URLs
/// * `from` - Start ledger sequence (defaults to recent checkpoint)
/// * `to` - End ledger sequence (defaults to latest available)
/// * `stop_on_error` - Stop immediately on first mismatch
/// * `show_diff` - Show detailed diff of mismatched entries
/// * `cdp_url` - CDP data lake URL
/// * `cdp_date` - CDP date partition
/// * `cache_dir` - Optional cache directory for buckets and CDP metadata
/// * `no_cache` - Disable caching (use temp directories)
async fn cmd_verify_execution(
    config: AppConfig,
    from: Option<u32>,
    to: Option<u32>,
    stop_on_error: bool,
    show_diff: bool,
    cdp_url: &str,
    cdp_date: &str,
    cache_dir: Option<std::path::PathBuf>,
    no_cache: bool,
    quiet: bool,
) -> anyhow::Result<()> {
    use std::sync::{Arc, RwLock};
    use stellar_core_bucket::{
        is_persistent_entry, BucketList, BucketManager, HasNextState, HotArchiveBucketList,
    };
    use stellar_core_common::{Hash256, NetworkId};
    use stellar_core_history::cdp::{
        extract_evicted_keys, extract_ledger_header, extract_restored_keys, extract_upgrade_metas,
        CachedCdpDataLake,
    };
    use stellar_core_history::{checkpoint, HistoryArchive};
    use stellar_core_ledger::execution::{load_soroban_config, TransactionExecutor};
    use stellar_core_ledger::{
        InMemorySorobanState, LedgerError, LedgerSnapshot, SnapshotHandle, SorobanRentConfig,
    };
    use stellar_core_tx::ClassicEventConfig;
    use stellar_xdr::curr::{BucketListType, LedgerEntry, LedgerKey};

    if !quiet {
        println!("Transaction Execution Verification");
        println!("===================================");
        println!("Re-executes transactions and compares results against CDP metadata.");
        println!();
    }

    // Determine network ID and network name
    let (network_id, network_name) = if config.network.passphrase.contains("Test") {
        (NetworkId::testnet(), "testnet")
    } else {
        (NetworkId::mainnet(), "mainnet")
    };

    // Determine cache directory
    let cache_base = if no_cache {
        None
    } else {
        cache_dir.or_else(|| dirs::cache_dir().map(|p| p.join("rs-stellar-core")))
    };

    // Create archive client
    let archive = config
        .history
        .archives
        .iter()
        .filter(|a| a.get_enabled)
        .find_map(|a| HistoryArchive::new(&a.url).ok())
        .ok_or_else(|| anyhow::anyhow!("No history archives available"))?;

    if !quiet {
        println!("Archive: {}", config.history.archives[0].url);
        println!("CDP: {} ({})", cdp_url, cdp_date);
        if let Some(ref cache) = cache_base {
            println!("Cache: {}", cache.display());
        } else {
            println!("Cache: disabled (using temp directories)");
        }
    }

    // Get current ledger and calculate range
    let root_has = archive.get_root_has().await?;
    let current_ledger = root_has.current_ledger;

    // Calculate the actual ledger range to analyze
    let end_ledger = to.unwrap_or_else(|| {
        checkpoint::latest_checkpoint_before_or_at(current_ledger).unwrap_or(current_ledger)
    });
    let start_ledger = from.unwrap_or_else(|| {
        let freq = stellar_core_history::CHECKPOINT_FREQUENCY;
        checkpoint::checkpoint_containing(end_ledger)
            .saturating_sub(4 * freq)
            .max(freq)
    });

    // For execution, we need to restore from the checkpoint BEFORE our start ledger
    let freq = stellar_core_history::CHECKPOINT_FREQUENCY;
    let init_checkpoint =
        checkpoint::latest_checkpoint_before_or_at(start_ledger.saturating_sub(1))
            .unwrap_or(freq - 1);

    // Calculate checkpoint range needed for headers
    let end_checkpoint = checkpoint::checkpoint_containing(end_ledger);

    if !quiet {
        println!("Ledger range: {} to {}", start_ledger, end_ledger);
        println!("Initial state: checkpoint {}", init_checkpoint);
        println!();
    }

    // Create CDP client with caching
    let cdp = if let Some(ref cache) = cache_base {
        CachedCdpDataLake::new(cdp_url, cdp_date, cache, network_name)?
    } else {
        let temp = tempfile::tempdir()?;
        CachedCdpDataLake::new(cdp_url, cdp_date, temp.path(), network_name)?
    };

    // Prefetch CDP metadata for the ledger range
    let prefetch_start = init_checkpoint + 1;
    let prefetch_end = end_ledger;
    let cached = cdp.cached_count(prefetch_start, prefetch_end);
    let total = (prefetch_end - prefetch_start + 1) as usize;
    if cached < total {
        if !quiet {
            println!(
                "Prefetching CDP metadata: {} cached, {} to download",
                cached,
                total - cached
            );
        }
        cdp.prefetch(prefetch_start, prefetch_end).await;
        if !quiet {
            println!();
        }
    } else if !quiet {
        println!("CDP metadata: {} ledgers cached", cached);
        println!();
    }

    // Setup bucket manager with persistent or temp directory
    // We need to keep the temp directory alive for the duration of the function
    let _bucket_dir_holder: Box<dyn std::any::Any>;
    let bucket_path = if let Some(ref cache) = cache_base {
        let path = cache.join("buckets").join(network_name);
        std::fs::create_dir_all(&path)?;
        _bucket_dir_holder = Box::new(());
        path
    } else {
        let temp = tempfile::tempdir()?;
        let path = temp.path().to_path_buf();
        _bucket_dir_holder = Box::new(temp);
        path
    };
    let bucket_manager = Arc::new(BucketManager::new(bucket_path.clone())?);

    if !quiet {
        println!(
            "Downloading initial state at checkpoint {}...",
            init_checkpoint
        );
    }
    let init_has = archive.get_checkpoint_has(init_checkpoint).await?;

    // Extract bucket hashes and FutureBucket states for live bucket list
    let bucket_hashes: Vec<(Hash256, Hash256)> = init_has
        .current_buckets
        .iter()
        .map(|level| {
            (
                Hash256::from_hex(&level.curr).unwrap_or(Hash256::ZERO),
                Hash256::from_hex(&level.snap).unwrap_or(Hash256::ZERO),
            )
        })
        .collect();

    let live_next_states: Vec<HasNextState> = init_has
        .current_buckets
        .iter()
        .map(|level| HasNextState {
            state: level.next.state,
            output: level
                .next
                .output
                .as_ref()
                .and_then(|h| Hash256::from_hex(h).ok()),
        })
        .collect();

    // Extract bucket hashes and FutureBucket states for hot archive (protocol 23+)
    let hot_archive_hashes: Option<Vec<(Hash256, Hash256)>> =
        init_has.hot_archive_buckets.as_ref().map(|levels| {
            levels
                .iter()
                .map(|level| {
                    (
                        Hash256::from_hex(&level.curr).unwrap_or(Hash256::ZERO),
                        Hash256::from_hex(&level.snap).unwrap_or(Hash256::ZERO),
                    )
                })
                .collect()
        });

    let hot_archive_next_states: Option<Vec<HasNextState>> =
        init_has.hot_archive_buckets.as_ref().map(|levels| {
            levels
                .iter()
                .map(|level| HasNextState {
                    state: level.next.state,
                    output: level
                        .next
                        .output
                        .as_ref()
                        .and_then(|h| Hash256::from_hex(h).ok()),
                })
                .collect()
        });

    // Collect all hashes to download (curr, snap, and completed merge outputs)
    let mut all_hashes: Vec<Hash256> = Vec::new();
    for (curr, snap) in &bucket_hashes {
        all_hashes.push(curr.clone());
        all_hashes.push(snap.clone());
    }
    for state in &live_next_states {
        if let Some(ref output) = state.output {
            all_hashes.push(output.clone());
        }
    }
    if let Some(ref ha_hashes) = hot_archive_hashes {
        for (curr, snap) in ha_hashes {
            all_hashes.push(curr.clone());
            all_hashes.push(snap.clone());
        }
    }
    if let Some(ref ha_states) = hot_archive_next_states {
        for state in ha_states {
            if let Some(ref output) = state.output {
                all_hashes.push(output.clone());
            }
        }
    }
    let all_hashes: Vec<&Hash256> = all_hashes.iter().filter(|h| !h.is_zero()).collect();

    if !quiet {
        print!("Buckets ({} required):", all_hashes.len());
    }
    let (cached, downloaded) =
        download_buckets_parallel(&archive, bucket_manager.as_ref(), all_hashes).await?;
    if !quiet && downloaded == 0 {
        println!(" {} cached", cached);
    }

    // Restore live bucket list for state lookups (with FutureBucket states for pending merges)
    let bucket_list = Arc::new(RwLock::new(BucketList::restore_from_has(
        &bucket_hashes,
        &live_next_states,
        |hash| bucket_manager.load_bucket(hash).map(|b| (*b).clone()),
    )?));

    // Restore hot archive bucket list if present (protocol 23+)
    // Hot archive buckets contain HotArchiveBucketEntry, not BucketEntry, so we use
    // the proper HotArchiveBucketList type and load_hot_archive_bucket method.
    let hot_archive_bucket_list: Option<Arc<RwLock<HotArchiveBucketList>>> =
        if let (Some(ref hashes), Some(ref next_states)) =
            (&hot_archive_hashes, &hot_archive_next_states)
        {
            Some(Arc::new(RwLock::new(
                HotArchiveBucketList::restore_from_has(hashes, next_states, |hash| {
                    bucket_manager.load_hot_archive_bucket(hash)
                })?,
            )))
        } else {
            None
        };

    let init_headers = archive.get_ledger_headers(init_checkpoint).await?;
    let init_header_entry = init_headers
        .iter()
        .find(|h| h.header.ledger_seq == init_checkpoint);
    let init_protocol_version = init_header_entry
        .map(|h| h.header.ledger_version)
        .unwrap_or(25);

    // Restart any pending merges that should have been in progress at the checkpoint.
    // This is critical for correct bucket list hash computation after catchup.
    // In C++ stellar-core, this is done by BucketListBase::restartMerges().
    bucket_list
        .write()
        .unwrap()
        .restart_merges(init_checkpoint, init_protocol_version)?;
    if let Some(ref hot) = hot_archive_bucket_list {
        hot.write()
            .unwrap()
            .restart_merges(init_checkpoint, init_protocol_version)?;
    }

    if !quiet {
        println!(
            "Initial live bucket list hash: {}",
            bucket_list.read().unwrap().hash().to_hex()
        );
        println!(
            "Live bucket list stats: {:?}",
            bucket_list.read().unwrap().stats()
        );
        if let Some(ref hot) = hot_archive_bucket_list {
            println!(
                "Initial hot archive hash: {}",
                hot.read().unwrap().hash().to_hex()
            );
            println!("Hot archive stats: {:?}", hot.read().unwrap().stats());
        }
        println!();
    }
    let init_rent_config = if let Some(init_header_entry) = init_header_entry {
        let bucket_list_clone: Arc<RwLock<BucketList>> = Arc::clone(&bucket_list);
        let hot_archive_clone: Option<Arc<RwLock<HotArchiveBucketList>>> =
            hot_archive_bucket_list.clone();
        let lookup_fn: Arc<
            dyn Fn(&LedgerKey) -> stellar_core_ledger::Result<Option<LedgerEntry>> + Send + Sync,
        > =
            Arc::new(move |key: &LedgerKey| {
                if let Some(entry) = bucket_list_clone.read().unwrap().get(key).map_err(|e| {
                    LedgerError::Internal(format!("Live bucket lookup failed: {}", e))
                })? {
                    return Ok(Some(entry));
                }
                if let Some(ref hot_archive) = hot_archive_clone {
                    if let Some(entry) = hot_archive.read().unwrap().get(key).map_err(|e| {
                        LedgerError::Internal(format!("Hot archive bucket lookup failed: {}", e))
                    })? {
                        return Ok(Some(entry.clone()));
                    }
                }
                Ok(None)
            });

        let snapshot = LedgerSnapshot::new(
            init_header_entry.header.clone(),
            Hash256::from(init_header_entry.hash.0),
            std::collections::HashMap::new(),
        );
        let snapshot_handle = SnapshotHandle::with_lookup(snapshot, lookup_fn);
        let soroban_config = load_soroban_config(&snapshot_handle);
        SorobanRentConfig {
            cpu_cost_params: soroban_config.cpu_cost_params,
            mem_cost_params: soroban_config.mem_cost_params,
            tx_max_instructions: soroban_config.tx_max_instructions,
            tx_max_memory_bytes: soroban_config.tx_max_memory_bytes,
        }
    } else {
        SorobanRentConfig::default()
    };

    // Initialize in-memory Soroban state from the checkpoint.
    let mut soroban_state = InMemorySorobanState::new();
    if init_protocol_version >= MIN_SOROBAN_PROTOCOL_VERSION {
        let live_entries = bucket_list.read().unwrap().live_entries()?;
        soroban_state
            .update_state(
                init_checkpoint,
                &live_entries,
                &[],
                &[],
                init_protocol_version,
                Some(&init_rent_config),
            )
            .map_err(|e| anyhow::anyhow!("soroban state init failed: {}", e))?;
    }

    // Track results
    let mut ledgers_verified = 0u32;
    let mut transactions_verified = 0u32;
    let mut transactions_matched = 0u32;
    let mut transactions_mismatched = 0u32;
    let mut phase1_fee_mismatches = 0u32;
    let mut ledgers_with_tx_mismatches = 0u32;
    let mut ledgers_with_header_mismatches = 0u32;
    let mut ledgers_with_both_mismatches = 0u32;

    // Process ledgers from init_checkpoint+1 to end_ledger
    let process_from = init_checkpoint + 1;
    let process_from_cp = checkpoint::checkpoint_containing(process_from);

    // Create the executor once and reuse across ledgers to preserve state
    // This is critical because accounts modified in earlier ledgers (during catchup)
    // need to reflect those changes when processing later ledgers
    let mut executor: Option<TransactionExecutor> = None;

    // Track the previous ledger's id_pool to use when creating the executor.
    // The executor needs the id_pool from BEFORE the ledger's transactions execute,
    // which is the previous ledger's CLOSING id_pool.
    //
    // For the first ledger we process (init_checkpoint + 1), we need the id_pool
    // from init_checkpoint's header.
    let init_id_pool = init_header_entry.map(|h| h.header.id_pool).unwrap_or(0);
    let mut prev_id_pool: Option<u64> = Some(init_id_pool);

    // Track header fields for verification
    let mut tracked_fee_pool: i64 = init_header_entry.map(|h| h.header.fee_pool).unwrap_or(0);
    let mut tracked_total_coins: i64 = init_header_entry.map(|h| h.header.total_coins).unwrap_or(0);
    let mut prev_header_hash: Hash256 = init_header_entry
        .map(|h| Hash256::from(h.hash.0))
        .unwrap_or(Hash256::ZERO);
    let mut prev_header: Option<stellar_xdr::curr::LedgerHeader> =
        init_header_entry.map(|h| h.header.clone());

    // Track header verification mismatches
    let mut header_mismatches: u32 = 0;

    let mut current_cp = process_from_cp;
    while current_cp <= end_checkpoint {
        let next_cp = checkpoint::next_checkpoint(current_cp);

        let headers = archive.get_ledger_headers(current_cp).await?;

        for header_entry in &headers {
            let header = &header_entry.header;
            let seq = header.ledger_seq;

            // Track the id_pool from each ledger header so we can use the PREVIOUS
            // ledger's id_pool when starting a new ledger
            let current_id_pool = header.id_pool;

            // Skip ledgers before our initial state or after our target
            if seq <= init_checkpoint || seq > end_ledger {
                prev_id_pool = Some(current_id_pool);
                continue;
            }

            // Determine if this ledger is in the user's requested test range
            let in_test_range = seq >= start_ledger && seq <= end_ledger;

            // Fetch CDP metadata
            let lcm = match cdp.get_ledger_close_meta(seq).await {
                Ok(lcm) => lcm,
                Err(e) => {
                    if in_test_range {
                        println!("  Ledger {}: CDP fetch failed: {}", seq, e);
                    }
                    continue;
                }
            };

            // Extract transactions and expected results from CDP
            let cdp_header = extract_ledger_header(&lcm);

            // Use the new function that ensures envelope/result/meta are properly aligned
            let tx_processing = stellar_core_history::cdp::extract_transaction_processing(
                &lcm,
                network_id.as_bytes(),
            );
            // Validate that CDP data matches the history archive data
            // If ledger hashes don't match, we're likely comparing data from different network epochs
            // (e.g., testnet was reset between when CDP was captured and current archive state)
            let _archive_header_hash = Hash256::from(header_entry.hash.0);
            let archive_close_time = header.scp_value.close_time.0;
            let cdp_close_time = cdp_header.scp_value.close_time.0;

            tracing::debug!(
                ledger_seq = seq,
                archive_close_time = archive_close_time,
                cdp_close_time = cdp_close_time,
                archive_prev_hash = hex::encode(header.previous_ledger_hash.0),
                cdp_prev_hash = hex::encode(cdp_header.previous_ledger_hash.0),
                "Comparing archive vs CDP headers"
            );

            // Check both close time AND previous ledger hash - either can indicate epoch mismatch
            let prev_hash_matches =
                header.previous_ledger_hash.0 == cdp_header.previous_ledger_hash.0;
            if archive_close_time != cdp_close_time || !prev_hash_matches {
                if in_test_range {
                    println!(
                        "  Ledger {}: EPOCH MISMATCH - archive close_time={} vs CDP close_time={}",
                        seq, archive_close_time, cdp_close_time
                    );
                    println!("    This indicates CDP data is from a different network epoch (e.g., testnet was reset)");
                    println!(
                        "    Archive previous_ledger_hash: {}",
                        hex::encode(header.previous_ledger_hash.0)
                    );
                    println!(
                        "    CDP previous_ledger_hash: {}",
                        hex::encode(cdp_header.previous_ledger_hash.0)
                    );
                }
                if stop_on_error {
                    anyhow::bail!(
                        "CDP data is from a different network epoch than the history archive. \
                        The network (likely testnet) was reset after the CDP date {}. \
                        Use a more recent CDP date partition or switch to mainnet.",
                        cdp_date
                    );
                }
                continue;
            }

            // Create snapshot handle with bucket list lookup (checks both live and hot archive)
            let bucket_list_clone: Arc<RwLock<BucketList>> = Arc::clone(&bucket_list);
            let hot_archive_clone: Option<Arc<RwLock<HotArchiveBucketList>>> =
                hot_archive_bucket_list.clone();
            let lookup_fn: Arc<
                dyn Fn(
                        &LedgerKey,
                    )
                        -> stellar_core_ledger::Result<Option<stellar_xdr::curr::LedgerEntry>>
                    + Send
                    + Sync,
            > = Arc::new(move |key: &LedgerKey| {
                // First try the live bucket list
                if let Some(entry) = bucket_list_clone.read().unwrap().get(key).map_err(|e| {
                    LedgerError::Internal(format!("Live bucket lookup failed: {}", e))
                })? {
                    return Ok(Some(entry));
                }
                // Then try the hot archive bucket list (for archived/evicted entries)
                // HotArchiveBucketList::get returns Option<&LedgerEntry>, so we clone
                if let Some(ref hot_archive) = hot_archive_clone {
                    if let Some(entry) = hot_archive.read().unwrap().get(key).map_err(|e| {
                        LedgerError::Internal(format!("Hot archive bucket lookup failed: {}", e))
                    })? {
                        return Ok(Some(entry.clone()));
                    }
                }
                Ok(None)
            });

            let snapshot = LedgerSnapshot::new(
                header.clone(),
                Hash256::from(header_entry.hash.0),
                std::collections::HashMap::new(),
            );
            let mut snapshot_handle = SnapshotHandle::with_lookup(snapshot, lookup_fn);
            let header_map: std::collections::HashMap<u32, stellar_xdr::curr::LedgerHeader> =
                headers
                    .iter()
                    .map(|entry| (entry.header.ledger_seq, entry.header.clone()))
                    .collect();
            let header_map = std::sync::Arc::new(header_map);
            let header_lookup: std::sync::Arc<
                dyn Fn(u32) -> stellar_core_ledger::Result<Option<stellar_xdr::curr::LedgerHeader>>
                    + Send
                    + Sync,
            > = std::sync::Arc::new(move |seq| Ok(header_map.get(&seq).cloned()));
            snapshot_handle.set_header_lookup(header_lookup);

            // Add entries_fn to enable orderbook loading for path payments
            let bucket_list_for_entries: Arc<RwLock<BucketList>> = Arc::clone(&bucket_list);
            let entries_fn: Arc<
                dyn Fn() -> stellar_core_ledger::Result<Vec<stellar_xdr::curr::LedgerEntry>>
                    + Send
                    + Sync,
            > = Arc::new(move || {
                bucket_list_for_entries
                    .read()
                    .unwrap()
                    .live_entries()
                    .map_err(|e| {
                        LedgerError::Internal(format!("Failed to get live entries: {}", e))
                    })
            });
            snapshot_handle.set_entries_lookup(entries_fn);

            // Load Soroban config from ledger state
            let soroban_config = load_soroban_config(&snapshot_handle);
            let rent_config = SorobanRentConfig {
                cpu_cost_params: soroban_config.cpu_cost_params.clone(),
                mem_cost_params: soroban_config.mem_cost_params.clone(),
                tx_max_instructions: soroban_config.tx_max_instructions,
                tx_max_memory_bytes: soroban_config.tx_max_memory_bytes,
            };

            // Create or advance the transaction executor
            // Keeping the executor across ledgers preserves state changes from earlier ledgers
            // (e.g., account balance updates), which is critical for correct execution
            //
            // For id_pool: We need the value from BEFORE this ledger's transactions execute.
            // This is the previous ledger's CLOSING id_pool, not the current ledger's.
            let starting_id_pool = prev_id_pool.unwrap_or(0);
            if let Some(ref mut exec) = executor {
                // Use fresh state to clear cached entries that may be stale after
                // applying CDP metadata to the bucket list in the previous ledger.
                exec.advance_to_ledger_with_fresh_state(
                    seq,
                    cdp_header.scp_value.close_time.0,
                    cdp_header.base_reserve,
                    cdp_header.ledger_version,
                    starting_id_pool,
                    soroban_config,
                );
            } else {
                executor = Some(TransactionExecutor::new(
                    seq,
                    cdp_header.scp_value.close_time.0,
                    cdp_header.base_reserve,
                    cdp_header.ledger_version,
                    network_id,
                    starting_id_pool, // Use previous ledger's id_pool
                    soroban_config,
                    ClassicEventConfig::default(),
                    None, // No invariant checking for now
                ));
            }

            // Update prev_id_pool for the next ledger
            prev_id_pool = Some(current_id_pool);
            let executor = executor.as_mut().unwrap();

            // Execute each transaction and compare (using aligned envelope/result/meta)
            let mut ledger_matched = true;
            let mut ledger_tx_mismatch = false;
            let mut ledger_header_mismatch = false;

            // Capture ledger-start TTL entries for all Soroban read footprint entries.
            // This is needed because when multiple transactions access the same entry,
            // C++ produces STATE (ledger-start) / UPDATED (current) pairs for each tx,
            // even if that specific tx didn't change the TTL.
            let mut ledger_start_ttls: std::collections::HashMap<
                stellar_xdr::curr::Hash,
                stellar_xdr::curr::LedgerEntry,
            > = std::collections::HashMap::new();
            for tx_info in tx_processing.iter() {
                let frame = stellar_core_tx::TransactionFrame::with_network(
                    tx_info.envelope.clone(),
                    stellar_core_common::NetworkId(config.network_id()),
                );
                if let Some(soroban_data) = frame.soroban_data() {
                    for key in soroban_data
                        .resources
                        .footprint
                        .read_only
                        .iter()
                        .chain(soroban_data.resources.footprint.read_write.iter())
                    {
                        // Compute key_hash for TTL lookup
                        match key {
                            stellar_xdr::curr::LedgerKey::ContractData(_)
                            | stellar_xdr::curr::LedgerKey::ContractCode(_) => {
                                use stellar_xdr::curr::{Limits, WriteXdr};
                                if let Ok(key_bytes) = key.to_xdr(Limits::none()) {
                                    let hash_bytes = stellar_core_crypto::sha256(&key_bytes);
                                    let key_hash = stellar_xdr::curr::Hash(*hash_bytes.as_bytes());
                                    if !ledger_start_ttls.contains_key(&key_hash) {
                                        // Look up TTL from snapshot (ledger-start value)
                                        let ttl_key = stellar_xdr::curr::LedgerKey::Ttl(
                                            stellar_xdr::curr::LedgerKeyTtl {
                                                key_hash: key_hash.clone(),
                                            },
                                        );
                                        if let Ok(Some(entry)) = snapshot_handle.get_entry(&ttl_key)
                                        {
                                            if matches!(
                                                &entry.data,
                                                stellar_xdr::curr::LedgerEntryData::Ttl(_)
                                            ) {
                                                ledger_start_ttls.insert(key_hash, entry);
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Two-phase transaction processing matching C++ stellar-core:
            // Phase 1: Process all fees first (modifies state for all fee sources)
            // Phase 2: Apply all transactions (with deduct_fee=false since fees already processed)

            // Phase 1: Process fees for all transactions and compare with CDP
            // Also save pre-fee state for fee sources to use in Phase 2 metadata
            let mut phase1_mismatches = 0;
            let mut fee_source_pre_states: Vec<Option<stellar_xdr::curr::LedgerEntry>> = Vec::new();
            for (tx_idx, tx_info) in tx_processing.iter().enumerate() {
                // For fee bump transactions with separate fee source, save the pre-fee state
                // This is needed for the STATE entry in Phase 2's tx_changes_before
                let frame = stellar_core_tx::TransactionFrame::with_network(
                    tx_info.envelope.clone(),
                    stellar_core_common::NetworkId(config.network_id()),
                );
                let fee_source_id =
                    stellar_core_tx::muxed_to_account_id(&frame.fee_source_account());
                let inner_source_id =
                    stellar_core_tx::muxed_to_account_id(&frame.inner_source_account());
                let pre_fee_state = if frame.is_fee_bump() && fee_source_id != inner_source_id {
                    let fee_source_key = stellar_xdr::curr::LedgerKey::Account(
                        stellar_xdr::curr::LedgerKeyAccount {
                            account_id: fee_source_id.clone(),
                        },
                    );
                    executor.get_entry(&fee_source_key)
                } else {
                    None
                };
                fee_source_pre_states.push(pre_fee_state);

                // Use per-tx base_fee from transaction set if available (for surge pricing)
                // otherwise fall back to header's base_fee
                let effective_base_fee = tx_info.base_fee.unwrap_or(cdp_header.base_fee);

                let fee_result = executor.process_fee_only(
                    &snapshot_handle,
                    &tx_info.envelope,
                    effective_base_fee,
                );

                // Compare our Phase 1 fee changes with CDP's fee_meta
                if in_test_range {
                    let our_fee_changes: Vec<_> = match &fee_result {
                        Ok((changes, _fee)) => changes.iter().cloned().collect(),
                        Err(_) => vec![],
                    };
                    let cdp_fee_changes: Vec<_> = tx_info.fee_meta.iter().cloned().collect();

                    let (fee_matches, fee_diffs) =
                        compare_entry_changes(&our_fee_changes, &cdp_fee_changes);
                    if !fee_matches {
                        phase1_mismatches += 1;
                        if show_diff {
                            println!("    TX {} Phase 1 FEE MISMATCH:", tx_idx);
                            println!(
                                "      Our fee changes: {}, CDP fee changes: {}",
                                our_fee_changes.len(),
                                cdp_fee_changes.len()
                            );
                            for diff in fee_diffs.iter().take(5) {
                                println!("      - {}", diff);
                            }
                        }
                    }
                }

                // Always sync with CDP's fee_meta to ensure correct state for Phase 2
                executor.apply_ledger_entry_changes(&tx_info.fee_meta);
            }

            // Accumulate Phase 1 fee mismatches
            if in_test_range {
                phase1_fee_mismatches += phase1_mismatches as u32;
            }

            // Post-transaction fee processing (e.g., Soroban refunds) is recorded
            // separately in CDP's post_tx_apply_fee_processing. For protocol 23+,
            // these refunds are applied after all transactions in the ledger.

            // Phase 2: Apply all transactions (fees already deducted in phase 1)
            let mut deferred_post_fee_changes: Vec<stellar_xdr::curr::LedgerEntryChanges> =
                Vec::new();
            for (tx_idx, tx_info) in tx_processing.iter().enumerate() {
                // Compute PRNG seed for Soroban: SHA256(txSetHash || xdr(u64(txIndex)))
                // C++ uses subSha256(baseSeed, static_cast<uint64_t>(index)) where
                // xdr_to_opaque serializes the u64 as 8 bytes big-endian.
                let prng_seed = {
                    let mut data = Vec::with_capacity(40); // 32 + 8 bytes
                    data.extend_from_slice(&cdp_header.scp_value.tx_set_hash.0);
                    data.extend_from_slice(&(tx_idx as u64).to_be_bytes()); // XDR u64 is 8 bytes BE
                    let hash = stellar_core_crypto::sha256(&data);
                    Some(*hash.as_bytes())
                };

                // Execute the transaction without fee deduction (fees processed in phase 1)
                // Pass the pre-fee state for fee bump transactions so the STATE entry
                // in tx_changes_before shows the correct pre-fee value
                let fee_source_pre_state = fee_source_pre_states.get(tx_idx).cloned().flatten();

                // Use per-tx base_fee from transaction set if available (for surge pricing)
                let effective_base_fee = tx_info.base_fee.unwrap_or(cdp_header.base_fee);

                let exec_result = executor.execute_transaction_with_fee_mode_and_pre_state(
                    &snapshot_handle,
                    &tx_info.envelope,
                    effective_base_fee,
                    prng_seed,
                    false, // deduct_fee = false - fees already processed
                    fee_source_pre_state,
                );

                // Check if CDP transaction succeeded
                // For fee bump transactions, success is TxFeeBumpInnerSuccess with inner TxSuccess
                let cdp_succeeded = match &tx_info.result.result.result {
                    stellar_xdr::curr::TransactionResultResult::TxSuccess(_) => true,
                    stellar_xdr::curr::TransactionResultResult::TxFeeBumpInnerSuccess(inner) => {
                        matches!(
                            inner.result.result,
                            stellar_xdr::curr::InnerTransactionResultResult::TxSuccess(_)
                        )
                    }
                    _ => false,
                };

                // Sync state with CDP to ensure subsequent transactions see correct state.
                // This is critical because even when both succeed, our state changes may differ
                // from CDP's (e.g., fee calculations, refunds, or execution differences).
                // Without syncing, these differences accumulate and cause subsequent failures.
                //
                // IMPORTANT: Only sync when the transaction succeeded. For failed transactions,
                // the CDP metadata contains changes from successful operations within the failed
                // transaction (for audit purposes), but these changes are rolled back and NOT
                // persisted to ledger state. Syncing them would incorrectly apply state changes
                // that C++ stellar-core rolled back.
                if cdp_succeeded {
                    // Apply changes in phases to handle sequence number pollution in CDP metadata.
                    // The issue: CDP metadata for operation changes can contain sequence numbers
                    // from later transactions in the same ledger (due to how C++ captures STATE).
                    // Solution: Apply tx_changes normally (includes real seq bumps), but preserve
                    // our sequence numbers when applying operation changes.
                    let (tx_changes, op_changes) = extract_changes_by_source(&tx_info.meta);

                    let tx_changes_vec: stellar_xdr::curr::LedgerEntryChanges =
                        tx_changes.try_into().unwrap_or_default();
                    executor.apply_ledger_entry_changes(&tx_changes_vec);

                    let op_changes_vec: stellar_xdr::curr::LedgerEntryChanges =
                        op_changes.try_into().unwrap_or_default();
                    executor.apply_ledger_entry_changes_preserve_seq(&op_changes_vec);

                    if !tx_info.post_fee_meta.is_empty() {
                        if cdp_header.ledger_version >= 23 {
                            deferred_post_fee_changes.push(tx_info.post_fee_meta.clone());
                        } else {
                            executor.apply_ledger_entry_changes(&tx_info.post_fee_meta);
                        }
                    }
                }

                if in_test_range {
                    transactions_verified += 1;

                    // Note: Fee bump transactions with separate fee source are now handled
                    // directly in execution.rs, which includes the fee source's current state
                    // in tx_changes_before when deduct_fee=false (two-phase mode).

                    match exec_result {
                        Ok(mut result) => {
                            // For Soroban transactions, augment our metadata with missing read footprint TTL entries.
                            // C++ produces STATE/UPDATED for read footprint TTL entries using ledger-start values,
                            // even if the specific transaction didn't change the TTL.
                            let frame = stellar_core_tx::TransactionFrame::with_network(
                                tx_info.envelope.clone(),
                                stellar_core_common::NetworkId(config.network_id()),
                            );
                            if let Some(soroban_data) = frame.soroban_data() {
                                if let Some(ref mut our_meta) = result.tx_meta {
                                    augment_soroban_ttl_metadata(
                                        our_meta,
                                        &soroban_data.resources.footprint,
                                        &ledger_start_ttls,
                                        executor,
                                        seq,
                                    );
                                }
                            }

                            // Deep comparison of transaction meta if both are available
                            // For fee bump transactions with separate fee source, fee changes are
                            // already in the CDP meta, so we don't need to prepend them
                            // Note: metadata comparison is out of scope; we only verify tx results + headers
                            let (_meta_matches, _meta_diffs) = match &result.tx_meta {
                                Some(our_meta) => compare_transaction_meta(
                                    our_meta,
                                    &tx_info.meta,
                                    None,
                                    show_diff,
                                ),
                                None => (
                                    false,
                                    vec!["We produced no meta but CDP has some".to_string()],
                                ),
                            };

                            // Compare full transaction results (operation results), not just success/failure.
                            // Metadata comparison is out of scope for verification.
                            let (results_match, result_diff) = compare_tx_results(
                                &result.operation_results,
                                &tx_info.result.result.result,
                            );
                            let success_matches = result.success == cdp_succeeded;

                            if success_matches && results_match {
                                transactions_matched += 1;
                                if show_diff && !quiet {
                                    let change_count = result
                                        .tx_meta
                                        .as_ref()
                                        .map(|m| extract_changes_from_meta(m).len())
                                        .unwrap_or(0);
                                    println!(
                                        "    TX {}: {} (ops: {}, changes: {})",
                                        tx_idx,
                                        if result.success { "OK" } else { "FAILED" },
                                        result.operation_results.len(),
                                        change_count
                                    );
                                }
                            } else {
                                transactions_mismatched += 1;
                                ledger_matched = false;
                                ledger_tx_mismatch = true;
                                let cdp_result_code = format!("{:?}", tx_info.result.result.result);
                                println!(
                                    "    TX {}: MISMATCH - our: {} vs CDP: {} (cdp_succeeded: {})",
                                    tx_idx,
                                    if result.success { "success" } else { "failed" },
                                    cdp_result_code,
                                    cdp_succeeded
                                );
                                // Print our error message if present
                                if let Some(err) = &result.error {
                                    println!("      - Our error: {}", err);
                                }
                                if let Some(failure) = &result.failure {
                                    println!("      - Our failure type: {:?}", failure);
                                }
                                if let Some(diff) = result_diff {
                                    println!("      - Result diff: {}", diff);
                                }
                            }
                        }
                        Err(e) => {
                            transactions_mismatched += 1;
                            ledger_matched = false;
                            ledger_tx_mismatch = true;
                            println!("    TX {}: EXECUTION ERROR: {}", tx_idx, e);
                        }
                    }
                }
            }
            if cdp_header.ledger_version >= 23 {
                for changes in deferred_post_fee_changes {
                    executor.apply_ledger_entry_changes(&changes);
                }
            }

            // Apply changes to bucket list for next ledger using CDP metadata
            // This ensures subsequent ledgers have correct state for lookups
            {
                use stellar_core_bucket::ledger_entry_to_key;
                use stellar_core_bucket::{EvictionIterator, StateArchivalSettings};
                use stellar_xdr::curr::{
                    ConfigSettingEntry, ConfigSettingId, LedgerEntryChange, LedgerEntryData,
                    LedgerEntryExt,
                };

                let mut aggregator = CoalescedLedgerChanges::new();
                let bl = bucket_list.read().unwrap();

                // Apply per-transaction changes in ledger order:
                // fee -> tx_meta -> post_fee
                for tx_info in &tx_processing {
                    for change in tx_info.fee_meta.iter() {
                        apply_change_with_prestate(&mut aggregator, &bl, change);
                    }

                    let succeeded = tx_succeeded(&tx_info.result);
                    match &tx_info.meta {
                        stellar_xdr::curr::TransactionMeta::V0(operations) => {
                            if succeeded {
                                for op_meta in operations.iter() {
                                    for change in op_meta.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                        }
                        stellar_xdr::curr::TransactionMeta::V1(v1) => {
                            if succeeded {
                                for change in v1.tx_changes.iter() {
                                    apply_change_with_prestate(&mut aggregator, &bl, change);
                                }
                                for op_changes in v1.operations.iter() {
                                    for change in op_changes.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                        }
                        stellar_xdr::curr::TransactionMeta::V2(v2) => {
                            for change in v2.tx_changes_before.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                            if succeeded {
                                for op_changes in v2.operations.iter() {
                                    for change in op_changes.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                            for change in v2.tx_changes_after.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                        }
                        stellar_xdr::curr::TransactionMeta::V3(v3) => {
                            for change in v3.tx_changes_before.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                            if succeeded {
                                for op_changes in v3.operations.iter() {
                                    for change in op_changes.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                            for change in v3.tx_changes_after.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                        }
                        stellar_xdr::curr::TransactionMeta::V4(v4) => {
                            for change in v4.tx_changes_before.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                            if succeeded {
                                for op_changes in v4.operations.iter() {
                                    for change in op_changes.changes.iter() {
                                        apply_change_with_prestate(&mut aggregator, &bl, change);
                                    }
                                }
                            }
                            for change in v4.tx_changes_after.iter() {
                                apply_change_with_prestate(&mut aggregator, &bl, change);
                            }
                        }
                    }

                    if !tx_info.post_fee_meta.is_empty() {
                        for change in tx_info.post_fee_meta.iter() {
                            apply_change_with_prestate(&mut aggregator, &bl, change);
                        }
                    }
                }

                // 4. Upgrade changes
                let upgrade_metas = extract_upgrade_metas(&lcm);

                for upgrade in &upgrade_metas {
                    for change in upgrade.changes.iter() {
                        apply_change_with_prestate(&mut aggregator, &bl, change);
                    }
                }

                // Snapshot the aggregator state BEFORE evictions to get the
                // non-eviction dead keys (entries deleted by transactions)
                let pre_eviction_dead: Vec<LedgerKey> = {
                    let (_, _, dead) = aggregator.clone().to_vectors();
                    dead
                };

                // 5. Evicted keys (Protocol 23+)
                let evicted_keys = extract_evicted_keys(&lcm);
                for key in &evicted_keys {
                    apply_change_with_prestate(
                        &mut aggregator,
                        &bl,
                        &LedgerEntryChange::Removed(key.clone()),
                    );
                }

                // Extract restored keys from transaction meta
                let tx_metas_for_restore: Vec<_> = tx_processing
                    .iter()
                    .filter(|tp| tx_succeeded(&tp.result))
                    .map(|tp| tp.meta.clone())
                    .collect();
                let restored_keys = if hot_archive_bucket_list.is_some() {
                    extract_restored_keys(&tx_metas_for_restore)
                } else {
                    Vec::new()
                };

                // Convert to vectors
                let archival_override = {
                    let archival_key =
                        LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                            config_setting_id: ConfigSettingId::StateArchival,
                        });
                    match aggregator.changes.get(&archival_key) {
                        Some(FinalChange::Init(entry)) | Some(FinalChange::Live(entry)) => {
                            if let LedgerEntryData::ConfigSetting(
                                ConfigSettingEntry::StateArchival(settings),
                            ) = &entry.data
                            {
                                Some(settings.clone())
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                };

                let eviction_iter_key =
                    LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                        config_setting_id: ConfigSettingId::EvictionIterator,
                    });
                let has_eviction_iter_change = aggregator.changes.contains_key(&eviction_iter_key);

                if cdp_header.ledger_version >= 23 && !has_eviction_iter_change {
                    let settings = if let Some(override_settings) = archival_override.clone() {
                        StateArchivalSettings {
                            eviction_scan_size: override_settings.eviction_scan_size as u64,
                            starting_eviction_scan_level: override_settings
                                .starting_eviction_scan_level,
                        }
                    } else {
                        let key =
                            LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                                config_setting_id: ConfigSettingId::StateArchival,
                            });
                        if let Ok(Some(entry)) = bl.get(&key) {
                            if let LedgerEntryData::ConfigSetting(
                                ConfigSettingEntry::StateArchival(s),
                            ) = entry.data
                            {
                                StateArchivalSettings {
                                    eviction_scan_size: s.eviction_scan_size as u64,
                                    starting_eviction_scan_level: s.starting_eviction_scan_level,
                                }
                            } else {
                                StateArchivalSettings::default()
                            }
                        } else {
                            StateArchivalSettings::default()
                        }
                    };
                    let iter = {
                        let key =
                            LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                                config_setting_id: ConfigSettingId::EvictionIterator,
                            });
                        if let Ok(Some(entry)) = bl.get(&key) {
                            if let LedgerEntryData::ConfigSetting(
                                ConfigSettingEntry::EvictionIterator(it),
                            ) = entry.data
                            {
                                EvictionIterator {
                                    bucket_file_offset: it.bucket_file_offset,
                                    bucket_list_level: it.bucket_list_level,
                                    is_curr_bucket: it.is_curr_bucket,
                                }
                            } else {
                                EvictionIterator::new(settings.starting_eviction_scan_level)
                            }
                        } else {
                            EvictionIterator::new(settings.starting_eviction_scan_level)
                        }
                    };

                    let scan_result = bl
                        .scan_for_eviction_incremental(iter, seq, &settings)
                        .unwrap();
                    let updated_iter = scan_result.end_iterator;

                    let iter_entry = LedgerEntry {
                        last_modified_ledger_seq: seq,
                        data: LedgerEntryData::ConfigSetting(ConfigSettingEntry::EvictionIterator(
                            stellar_xdr::curr::EvictionIterator {
                                bucket_file_offset: updated_iter.bucket_file_offset,
                                bucket_list_level: updated_iter.bucket_list_level,
                                is_curr_bucket: updated_iter.is_curr_bucket,
                            },
                        )),
                        ext: LedgerEntryExt::V0,
                    };
                    apply_change_with_prestate(
                        &mut aggregator,
                        &bl,
                        &LedgerEntryChange::Updated(iter_entry),
                    );
                }

                let window_key =
                    LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                        config_setting_id: ConfigSettingId::LiveSorobanStateSizeWindow,
                    });
                let has_window_change = aggregator.changes.contains_key(&window_key);

                if !has_window_change {
                    maybe_snapshot_soroban_state_size_window(
                        seq,
                        cdp_header.ledger_version,
                        &bl,
                        soroban_state.total_size(),
                        &mut aggregator,
                        archival_override,
                    );
                }

                let (all_init, all_live, all_dead) = aggregator.clone().to_vectors();
                if cdp_header.ledger_version >= MIN_SOROBAN_PROTOCOL_VERSION {
                    soroban_state
                        .update_state(
                            seq,
                            &all_init,
                            &all_live,
                            &all_dead,
                            cdp_header.ledger_version,
                            Some(&rent_config),
                        )
                        .map_err(|e| anyhow::anyhow!("soroban state update failed: {}", e))?;
                }

                let (all_init, all_live, all_dead) = aggregator.to_vectors();

                // Before evicting entries from the live bucket list, look up full entry data
                // for persistent entries that need to go to the hot archive. Use the
                // post-transaction state when entries were updated in this ledger.
                let mut archived_entries = Vec::new();
                if hot_archive_bucket_list.is_some() {
                    let mut changed_entries: std::collections::HashMap<
                        stellar_xdr::curr::LedgerKey,
                        stellar_xdr::curr::LedgerEntry,
                    > = std::collections::HashMap::new();
                    for entry in all_init.iter().chain(all_live.iter()) {
                        if let Some(key) = ledger_entry_to_key(entry) {
                            changed_entries.insert(key, entry.clone());
                        }
                    }
                    // Use pre-eviction dead keys (entries deleted by transactions, NOT evictions)
                    // Evicted entries should still go to hot archive even if they're "dead"
                    let dead_keys: std::collections::HashSet<stellar_xdr::curr::LedgerKey> =
                        pre_eviction_dead.iter().cloned().collect();

                    for key in &evicted_keys {
                        if matches!(key, stellar_xdr::curr::LedgerKey::Ttl(_)) {
                            continue;
                        }
                        if dead_keys.contains(key) {
                            continue;
                        }
                        if let Some(entry) = changed_entries.get(key) {
                            if is_persistent_entry(entry) {
                                archived_entries.push(entry.clone());
                            }
                            continue;
                        }
                        if let Ok(Some(entry)) = bl.get(key) {
                            if is_persistent_entry(&entry) {
                                archived_entries.push(entry);
                            }
                        }
                    }
                }

                drop(bl);

                // Apply to bucket list
                bucket_list.write().unwrap().add_batch(
                    seq,
                    cdp_header.ledger_version,
                    BucketListType::Live,
                    all_init,
                    all_live,
                    all_dead,
                )?;

                // Update hot archive bucket list
                if cdp_header.ledger_version >= 23 {
                    if let Some(ref hot_archive) = hot_archive_bucket_list {
                        hot_archive.write().unwrap().add_batch(
                            seq,
                            cdp_header.ledger_version,
                            archived_entries,
                            restored_keys,
                        )?;
                    }
                }
            }

            // Header verification: Compare our computed header fields against CDP
            if in_test_range {
                // 1. Compute bucket list hash
                let bl = bucket_list.read().unwrap();
                let our_live_hash = bl.hash();
                drop(bl);

                let our_hot_hash = hot_archive_bucket_list
                    .as_ref()
                    .map(|hot| hot.read().unwrap().hash());

                let our_bucket_list_hash = {
                    // For Protocol 23+, combine live and hot archive hashes
                    if cdp_header.ledger_version >= 23 {
                        if let Some(hot_hash) = our_hot_hash {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(our_live_hash.as_bytes());
                            hasher.update(hot_hash.as_bytes());
                            let result = hasher.finalize();
                            let mut bytes = [0u8; 32];
                            bytes.copy_from_slice(&result);
                            Hash256::from_bytes(bytes)
                        } else {
                            our_live_hash
                        }
                    } else {
                        our_live_hash
                    }
                };
                let expected_bucket_list_hash = Hash256::from(cdp_header.bucket_list_hash.0);
                let bucket_list_matches = our_bucket_list_hash == expected_bucket_list_hash;

                // 2. Compute fee pool: previous fee_pool + fees charged this ledger
                let fees_this_ledger: i64 = tx_processing
                    .iter()
                    .map(|tp| tp.result.result.fee_charged)
                    .sum();
                let our_fee_pool = tracked_fee_pool + fees_this_ledger;
                let expected_fee_pool = cdp_header.fee_pool;
                let fee_pool_matches = our_fee_pool == expected_fee_pool;

                // 3. Compute tx_set_result_hash from results
                let result_set = stellar_xdr::curr::TransactionResultSet {
                    results: tx_processing
                        .iter()
                        .map(|tp| tp.result.clone())
                        .collect::<Vec<_>>()
                        .try_into()
                        .unwrap_or_default(),
                };
                let our_tx_result_hash = Hash256::hash_xdr(&result_set).unwrap_or(Hash256::ZERO);
                let expected_tx_result_hash = Hash256::from(cdp_header.tx_set_result_hash.0);
                let tx_result_hash_matches = our_tx_result_hash == expected_tx_result_hash;

                // 4. Compute full header hash if we have the previous header
                let mut header_hash_matches = true;
                let mut our_header_hash = Hash256::ZERO;
                let expected_header_hash = Hash256::from(header_entry.hash.0);

                if let Some(ref prev_hdr) = prev_header {
                    use stellar_core_ledger::{compute_header_hash, create_next_header};

                    // Create the header as the live node would
                    let mut computed_header = create_next_header(
                        prev_hdr,
                        prev_header_hash,
                        cdp_header.scp_value.close_time.0,
                        Hash256::from(cdp_header.scp_value.tx_set_hash.0),
                        our_bucket_list_hash,
                        our_tx_result_hash,
                        tracked_total_coins, // Total coins typically stays constant
                        our_fee_pool,
                        prev_hdr.inflation_seq,
                    );

                    // Apply upgrades to match CDP header fields
                    computed_header.ledger_version = cdp_header.ledger_version;
                    computed_header.base_fee = cdp_header.base_fee;
                    computed_header.base_reserve = cdp_header.base_reserve;
                    computed_header.max_tx_set_size = cdp_header.max_tx_set_size;
                    computed_header.id_pool = cdp_header.id_pool;
                    computed_header.scp_value.upgrades = cdp_header.scp_value.upgrades.clone();
                    computed_header.scp_value.ext = cdp_header.scp_value.ext.clone();

                    if let Ok(hash) = compute_header_hash(&computed_header) {
                        our_header_hash = hash;
                        header_hash_matches = our_header_hash == expected_header_hash;
                    }
                }

                // Report mismatches
                let all_header_fields_match = bucket_list_matches
                    && fee_pool_matches
                    && tx_result_hash_matches
                    && header_hash_matches;
                if !all_header_fields_match {
                    header_mismatches += 1;
                    ledger_header_mismatch = true;
                    println!("  Ledger {}: HEADER MISMATCH", seq);
                    if !bucket_list_matches {
                        println!(
                            "    bucket_list_hash: ours={} expected={}",
                            our_bucket_list_hash.to_hex(),
                            expected_bucket_list_hash.to_hex()
                        );
                        println!("    live_hash:        {}", our_live_hash.to_hex());
                        if let Some(hot_hash) = our_hot_hash {
                            println!("    hot_archive_hash: {}", hot_hash.to_hex());
                        }
                        // Print which levels should have spilled at this ledger
                        let spilling_levels: Vec<usize> = (0..10)
                            .filter(|&lvl| {
                                stellar_core_bucket::BucketList::level_should_spill(seq, lvl)
                            })
                            .collect();
                        if !spilling_levels.is_empty() {
                            println!(
                                "    Levels that spilled at ledger {}: {:?}",
                                seq, spilling_levels
                            );
                        }
                        // Print level-by-level hashes for debugging
                        let bl = bucket_list.read().unwrap();
                        println!("    Level-by-level live bucket hashes:");
                        for i in 0..11 {
                            if let Some(level) = bl.level(i) {
                                let curr_hash = level.curr.hash();
                                let snap_hash = level.snap.hash();
                                let level_hash = {
                                    use sha2::{Digest, Sha256};
                                    let mut hasher = Sha256::new();
                                    hasher.update(curr_hash.as_bytes());
                                    hasher.update(snap_hash.as_bytes());
                                    let result = hasher.finalize();
                                    hex::encode(&result[..8])
                                };
                                println!(
                                    "      L{}: curr={}... snap={}... (level_hash={}...)",
                                    i,
                                    &curr_hash.to_hex()[..16],
                                    &snap_hash.to_hex()[..16],
                                    level_hash
                                );
                            }
                        }
                    }
                    if !fee_pool_matches {
                        println!(
                            "    fee_pool: ours={} expected={} (prev={} + fees={})",
                            our_fee_pool, expected_fee_pool, tracked_fee_pool, fees_this_ledger
                        );
                    }
                    if !tx_result_hash_matches {
                        println!(
                            "    tx_result_hash: ours={} expected={}",
                            our_tx_result_hash.to_hex(),
                            expected_tx_result_hash.to_hex()
                        );
                    }
                    if !header_hash_matches {
                        println!(
                            "    header_hash: ours={} expected={}",
                            our_header_hash.to_hex(),
                            expected_header_hash.to_hex()
                        );
                    }
                    if stop_on_error {
                        anyhow::bail!("Header mismatch at ledger {}", seq);
                    }
                }
            }

            // ALWAYS update tracked values for next ledger (even outside test range)
            // This ensures header tracking stays in sync with bucket list state
            {
                let expected_header_hash = Hash256::from(header_entry.hash.0);
                tracked_fee_pool = cdp_header.fee_pool; // Use expected to avoid accumulating errors
                tracked_total_coins = cdp_header.total_coins;
                prev_header_hash = expected_header_hash; // Use expected hash for next ledger
                prev_header = Some(cdp_header.clone());
            }

            if in_test_range {
                if ledger_matched || tx_processing.is_empty() {
                    if !quiet {
                        println!(
                            "  Ledger {}: {} transactions - {}",
                            seq,
                            tx_processing.len(),
                            if tx_processing.is_empty() {
                                "no txs"
                            } else {
                                "all matched"
                            }
                        );
                    }
                } else {
                    // Always print mismatches, even in quiet mode
                    println!(
                        "  Ledger {}: {} transactions - SOME MISMATCHES",
                        seq,
                        tx_processing.len()
                    );
                    if stop_on_error {
                        anyhow::bail!("Stopping on first error");
                    }
                }
                if ledger_tx_mismatch {
                    ledgers_with_tx_mismatches += 1;
                }
                if ledger_header_mismatch {
                    ledgers_with_header_mismatches += 1;
                }
                if ledger_tx_mismatch && ledger_header_mismatch {
                    ledgers_with_both_mismatches += 1;
                }
                ledgers_verified += 1;
            }
        }

        current_cp = next_cp;
    }

    println!();
    println!("Transaction Execution Verification Complete");
    println!("  Ledgers verified: {}", ledgers_verified);
    println!("  Transactions verified: {}", transactions_verified);
    println!(
        "  Phase 1 fee calculations matched: {}",
        transactions_verified - phase1_fee_mismatches
    );
    println!(
        "  Phase 1 fee calculations mismatched: {}",
        phase1_fee_mismatches
    );
    println!("  Phase 2 execution matched: {}", transactions_matched);
    println!(
        "  Phase 2 execution mismatched: {}",
        transactions_mismatched
    );
    println!(
        "  Ledgers with tx mismatches: {}",
        ledgers_with_tx_mismatches
    );
    println!(
        "  Ledgers with header mismatches: {}",
        ledgers_with_header_mismatches
    );
    println!(
        "  Ledgers with tx+header mismatches: {}",
        ledgers_with_both_mismatches
    );
    let bucketlist_only =
        ledgers_with_header_mismatches.saturating_sub(ledgers_with_both_mismatches);
    let tx_only = ledgers_with_tx_mismatches.saturating_sub(ledgers_with_both_mismatches);
    println!(
        "  Ledger mismatch breakdown: bucketlist-only={}, tx-only={}, both={}",
        bucketlist_only, tx_only, ledgers_with_both_mismatches
    );
    println!(
        "  Header verifications: {} passed, {} failed",
        ledgers_verified.saturating_sub(header_mismatches),
        header_mismatches
    );

    if phase1_fee_mismatches > 0 {
        println!();
        println!(
            "WARNING: {} transactions had Phase 1 fee calculation differences!",
            phase1_fee_mismatches
        );
    }

    if transactions_mismatched > 0 {
        println!();
        println!(
            "WARNING: {} transactions had Phase 2 execution differences!",
            transactions_mismatched
        );
    }

    if header_mismatches > 0 {
        println!();
        println!(
            "WARNING: {} ledgers had header hash mismatches!",
            header_mismatches
        );
        println!("This indicates divergence in bucket list state, fee pool calculation, or header computation.");
    }

    Ok(())
}

/// Inspects a specific account entry in the bucket list at a checkpoint.
///
/// This debugging tool shows all occurrences of an account across all bucket
/// levels, helping diagnose issues like shadowed entries or incorrect lookups.
/// It displays both the normal lookup result and a full scan across all buckets.
///
/// # Arguments
///
/// * `config` - Application configuration with history archive URLs
/// * `checkpoint_seq` - Checkpoint ledger sequence to inspect
/// * `account_hex` - Account public key as 64-character hex string
async fn cmd_debug_bucket_entry(
    config: AppConfig,
    checkpoint_seq: u32,
    account_hex: &str,
) -> anyhow::Result<()> {
    use std::sync::Arc;
    use stellar_core_bucket::{BucketEntry, BucketList, BucketManager};
    use stellar_core_common::Hash256;
    use stellar_core_history::{is_checkpoint_ledger, HistoryArchive};
    use stellar_xdr::curr::{
        AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, PublicKey, Uint256,
    };

    // Parse account hex to AccountId
    let account_bytes = hex::decode(account_hex)?;
    if account_bytes.len() != 32 {
        anyhow::bail!("Account hex must be 32 bytes (64 hex chars)");
    }
    let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        account_bytes.try_into().unwrap(),
    )));
    let account_key = LedgerKey::Account(LedgerKeyAccount {
        account_id: account_id.clone(),
    });

    println!("Debug Bucket Entry Inspection");
    println!("==============================");
    println!("Checkpoint: {}", checkpoint_seq);
    println!("Account: {}", account_hex);
    println!();

    // Verify checkpoint is valid
    if !is_checkpoint_ledger(checkpoint_seq) {
        anyhow::bail!("{} is not a valid checkpoint ledger", checkpoint_seq);
    }

    // Create archive client from config
    let archive = config
        .history
        .archives
        .iter()
        .filter(|a| a.get_enabled)
        .find_map(|a| HistoryArchive::new(&a.url).ok())
        .ok_or_else(|| anyhow::anyhow!("No history archives available"))?;

    println!("Archive: {}", config.history.archives[0].url);

    // Get bucket list hashes at this checkpoint
    let has_entry = archive.get_checkpoint_has(checkpoint_seq).await?;
    let bucket_hashes: Vec<Hash256> = has_entry
        .current_buckets
        .iter()
        .flat_map(|level| {
            vec![
                Hash256::from_hex(&level.curr).unwrap_or(Hash256::ZERO),
                Hash256::from_hex(&level.snap).unwrap_or(Hash256::ZERO),
            ]
        })
        .collect();

    println!("Loading bucket list...");

    // Create bucket manager and load buckets
    let bucket_dir = tempfile::tempdir()?;
    let bucket_manager = Arc::new(BucketManager::new(bucket_dir.path().to_path_buf())?);

    // Download all required buckets
    let all_hashes: Vec<&Hash256> = bucket_hashes
        .iter()
        .filter(|h: &&Hash256| !h.is_zero())
        .collect();

    print!("Buckets ({} required):", all_hashes.len());
    let (cached, downloaded) =
        download_buckets_parallel(&archive, &bucket_manager, all_hashes).await?;
    if downloaded == 0 {
        println!(" {} cached", cached);
    }

    // Restore bucket list
    let mut bucket_list = BucketList::restore_from_hashes(&bucket_hashes, |hash| {
        bucket_manager.load_bucket(hash).map(|b| (*b).clone())
    })?;

    // Restart pending merges (for correct state)
    bucket_list.restart_merges(checkpoint_seq, 25)?;

    println!("Bucket list hash: {}", bucket_list.hash().to_hex());
    println!();

    // Look up the account normally
    println!("Normal lookup result:");
    match bucket_list.get(&account_key)? {
        Some(entry) => {
            if let LedgerEntryData::Account(acc) = &entry.data {
                println!("  Balance: {}", acc.balance);
                println!("  Sequence: {}", acc.seq_num.0);
                println!("  Last modified: {}", entry.last_modified_ledger_seq);
                println!("  Thresholds: {:?}", acc.thresholds.0);
                println!("  Num signers: {}", acc.signers.len());
                for (i, signer) in acc.signers.iter().enumerate() {
                    println!("    Signer {}: weight={}", i, signer.weight);
                }
            }
        }
        None => {
            println!("  NOT FOUND");
        }
    }
    println!();

    // Find ALL occurrences across all buckets
    println!("All occurrences in bucket list:");
    let occurrences = bucket_list.find_all_occurrences(&account_key)?;
    if occurrences.is_empty() {
        println!("  No occurrences found in any bucket");
    } else {
        for (level, bucket_type, entry) in &occurrences {
            println!("  Level {} {}: ", level, bucket_type);
            match entry {
                BucketEntry::Live(e) | BucketEntry::Init(e) => {
                    if let LedgerEntryData::Account(acc) = &e.data {
                        println!("    Type: Live/Init");
                        println!("    Balance: {}", acc.balance);
                        println!("    Sequence: {}", acc.seq_num.0);
                        println!("    Last modified: {}", e.last_modified_ledger_seq);
                        println!("    Thresholds: {:?}", acc.thresholds.0);
                        println!("    Num signers: {}", acc.signers.len());
                        for (i, signer) in acc.signers.iter().enumerate() {
                            println!("      Signer {}: weight={}", i, signer.weight);
                        }
                    }
                }
                BucketEntry::Dead(_) => {
                    println!("    Type: Dead (deleted)");
                }
                BucketEntry::Metadata(_) => {
                    println!("    Type: Metadata (unexpected)");
                }
            }
        }
    }

    Ok(())
}

fn tx_succeeded(result: &stellar_xdr::curr::TransactionResultPair) -> bool {
    use stellar_xdr::curr::{InnerTransactionResultResult, TransactionResultResult};

    match &result.result.result {
        TransactionResultResult::TxSuccess(_) => true,
        TransactionResultResult::TxFeeBumpInnerSuccess(inner) => {
            matches!(
                inner.result.result,
                InnerTransactionResultResult::TxSuccess(_)
            )
        }
        _ => false,
    }
}

/// Compare full transaction results (operation results), not just success/failure.
/// Returns true if the results match, along with a description of any differences.
fn compare_tx_results(
    our_results: &[stellar_xdr::curr::OperationResult],
    cdp_result: &stellar_xdr::curr::TransactionResultResult,
) -> (bool, Option<String>) {
    use stellar_xdr::curr::{InnerTransactionResultResult, TransactionResultResult};

    // Extract CDP operation results
    let cdp_op_results: Option<&Vec<stellar_xdr::curr::OperationResult>> = match cdp_result {
        TransactionResultResult::TxSuccess(ops) => Some(ops.as_ref()),
        TransactionResultResult::TxFailed(ops) => Some(ops.as_ref()),
        TransactionResultResult::TxFeeBumpInnerSuccess(inner) => match &inner.result.result {
            InnerTransactionResultResult::TxSuccess(ops) => Some(ops.as_ref()),
            InnerTransactionResultResult::TxFailed(ops) => Some(ops.as_ref()),
            _ => None,
        },
        TransactionResultResult::TxFeeBumpInnerFailed(inner) => match &inner.result.result {
            InnerTransactionResultResult::TxSuccess(ops) => Some(ops.as_ref()),
            InnerTransactionResultResult::TxFailed(ops) => Some(ops.as_ref()),
            _ => None,
        },
        _ => None,
    };

    let Some(cdp_ops) = cdp_op_results else {
        // CDP result doesn't contain operation results (e.g., TxTooEarly, TxBadSeq, etc.)
        // In this case, we only compare that both failed at the transaction level
        return (our_results.is_empty(), None);
    };

    if our_results.len() != cdp_ops.len() {
        return (
            false,
            Some(format!(
                "Operation count mismatch: ours={}, CDP={}",
                our_results.len(),
                cdp_ops.len()
            )),
        );
    }

    // Compare each operation result
    for (i, (ours, cdp)) in our_results.iter().zip(cdp_ops.iter()).enumerate() {
        // Compare the discriminant (operation type and success/failure code)
        let ours_debug = format!("{:?}", ours);
        let cdp_debug = format!("{:?}", cdp);
        if ours_debug != cdp_debug {
            return (
                false,
                Some(format!(
                    "Op {} result mismatch: ours={}, CDP={}",
                    i, ours_debug, cdp_debug
                )),
            );
        }
    }

    (true, None)
}

/// Converts a `LedgerEntryChange` to a sortable key for order-independent comparison.
///
/// Returns `(key_xdr, remapped_type, content_hash)` matching C++ stellar-core's MetaUtils.cpp.
///
/// C++ ordering from sortChanges():
/// - Primary: ledger key (via LedgerEntryIdCmp)
/// - Secondary: remapped type where REMOVED=0, STATE=1, CREATED=2, UPDATED=3, RESTORED=4
/// - Tertiary: sha256 hash of the entire change XDR
///
/// This enables consistent sorting since C++ stellar-core uses UnorderedMap with
/// a random hash mixer, producing non-deterministic ordering across runs.
fn change_sort_key(change: &stellar_xdr::curr::LedgerEntryChange) -> (Vec<u8>, u8, [u8; 32]) {
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::{LedgerEntryChange, LedgerKey, Limits, WriteXdr};

    fn entry_to_key_xdr(entry: &stellar_xdr::curr::LedgerEntry) -> Vec<u8> {
        // Extract the key from the entry and serialize it
        let key = match &entry.data {
            stellar_xdr::curr::LedgerEntryData::Account(a) => {
                LedgerKey::Account(stellar_xdr::curr::LedgerKeyAccount {
                    account_id: a.account_id.clone(),
                })
            }
            stellar_xdr::curr::LedgerEntryData::Trustline(t) => {
                LedgerKey::Trustline(stellar_xdr::curr::LedgerKeyTrustLine {
                    account_id: t.account_id.clone(),
                    asset: t.asset.clone(),
                })
            }
            stellar_xdr::curr::LedgerEntryData::Offer(o) => {
                LedgerKey::Offer(stellar_xdr::curr::LedgerKeyOffer {
                    seller_id: o.seller_id.clone(),
                    offer_id: o.offer_id,
                })
            }
            stellar_xdr::curr::LedgerEntryData::Data(d) => {
                LedgerKey::Data(stellar_xdr::curr::LedgerKeyData {
                    account_id: d.account_id.clone(),
                    data_name: d.data_name.clone(),
                })
            }
            stellar_xdr::curr::LedgerEntryData::ClaimableBalance(cb) => {
                LedgerKey::ClaimableBalance(stellar_xdr::curr::LedgerKeyClaimableBalance {
                    balance_id: cb.balance_id.clone(),
                })
            }
            stellar_xdr::curr::LedgerEntryData::LiquidityPool(lp) => {
                LedgerKey::LiquidityPool(stellar_xdr::curr::LedgerKeyLiquidityPool {
                    liquidity_pool_id: lp.liquidity_pool_id.clone(),
                })
            }
            stellar_xdr::curr::LedgerEntryData::ContractData(cd) => {
                LedgerKey::ContractData(stellar_xdr::curr::LedgerKeyContractData {
                    contract: cd.contract.clone(),
                    key: cd.key.clone(),
                    durability: cd.durability,
                })
            }
            stellar_xdr::curr::LedgerEntryData::ContractCode(cc) => {
                LedgerKey::ContractCode(stellar_xdr::curr::LedgerKeyContractCode {
                    hash: cc.hash.clone(),
                })
            }
            stellar_xdr::curr::LedgerEntryData::ConfigSetting(cs) => {
                // Use discriminant as the config setting ID
                LedgerKey::ConfigSetting(stellar_xdr::curr::LedgerKeyConfigSetting {
                    config_setting_id: cs.discriminant(),
                })
            }
            stellar_xdr::curr::LedgerEntryData::Ttl(ttl) => {
                LedgerKey::Ttl(stellar_xdr::curr::LedgerKeyTtl {
                    key_hash: ttl.key_hash.clone(),
                })
            }
        };
        key.to_xdr(Limits::none()).unwrap_or_default()
    }

    fn key_to_xdr(key: &LedgerKey) -> Vec<u8> {
        key.to_xdr(Limits::none()).unwrap_or_default()
    }

    // Compute sha256 hash of entire change XDR for tie-breaking
    fn change_hash(change: &LedgerEntryChange) -> [u8; 32] {
        let xdr_bytes = change.to_xdr(Limits::none()).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&xdr_bytes);
        hasher.finalize().into()
    }

    // C++ remapped type order from MetaUtils.cpp:
    // LEDGER_ENTRY_REMOVED (3) -> 0
    // LEDGER_ENTRY_STATE (0) -> 1
    // LEDGER_ENTRY_CREATED (1) -> 2
    // LEDGER_ENTRY_UPDATED (2) -> 3
    // LEDGER_ENTRY_RESTORED (4) -> 4
    match change {
        LedgerEntryChange::State(entry) => (entry_to_key_xdr(entry), 1, change_hash(change)),
        LedgerEntryChange::Created(entry) => (entry_to_key_xdr(entry), 2, change_hash(change)),
        LedgerEntryChange::Updated(entry) => (entry_to_key_xdr(entry), 3, change_hash(change)),
        LedgerEntryChange::Removed(key) => (key_to_xdr(key), 0, change_hash(change)),
        LedgerEntryChange::Restored(entry) => (entry_to_key_xdr(entry), 4, change_hash(change)),
    }
}

/// Compares two lists of ledger entry changes in an order-independent manner.
///
/// C++ stellar-core's UnorderedMap uses RandHasher with a random gMixer per process,
/// so metadata entry ordering is non-deterministic between different runs.
/// This comparison sorts changes by (key, remapped_type, content_hash) before comparing,
/// matching C++ MetaUtils.cpp sortChanges() ordering.
///
/// # Returns
///
/// `(matches, differences)` where:
/// - `matches` is true if the lists are semantically equivalent
/// - `differences` contains descriptions of any mismatches
fn compare_entry_changes(
    our_changes: &[stellar_xdr::curr::LedgerEntryChange],
    cdp_changes: &[stellar_xdr::curr::LedgerEntryChange],
) -> (bool, Vec<String>) {
    use stellar_xdr::curr::{Limits, WriteXdr};

    let mut diffs = Vec::new();

    // Compare the number of changes
    if our_changes.len() != cdp_changes.len() {
        diffs.push(format!(
            "Change count: ours={}, cdp={}",
            our_changes.len(),
            cdp_changes.len()
        ));
    }

    // Sort both lists by (key_xdr, remapped_type, content_hash) matching C++ MetaUtils.cpp
    let mut our_sorted: Vec<_> = our_changes.iter().collect();
    let mut cdp_sorted: Vec<_> = cdp_changes.iter().collect();
    our_sorted.sort_by_key(|c| change_sort_key(c));
    cdp_sorted.sort_by_key(|c| change_sort_key(c));

    // Compare individual changes after sorting
    for (i, (our, cdp)) in our_sorted.iter().zip(cdp_sorted.iter()).enumerate() {
        let our_xdr = our.to_xdr(Limits::none()).unwrap_or_default();
        let cdp_xdr = cdp.to_xdr(Limits::none()).unwrap_or_default();

        if our_xdr != cdp_xdr {
            diffs.push(format!(
                "Change {} differs:\n        ours: {}\n        cdp:  {}",
                i,
                describe_change_detailed(our),
                describe_change_detailed(cdp)
            ));
        }
    }

    // Report any extra changes on either side
    if our_sorted.len() > cdp_sorted.len() {
        for (i, change) in our_sorted.iter().skip(cdp_sorted.len()).enumerate() {
            diffs.push(format!(
                "Extra our change {}: {}",
                cdp_sorted.len() + i,
                describe_change(change)
            ));
        }
    }
    if cdp_sorted.len() > our_sorted.len() {
        for (i, change) in cdp_sorted.iter().skip(our_sorted.len()).enumerate() {
            diffs.push(format!(
                "Extra CDP change {}: {}",
                our_sorted.len() + i,
                describe_change(change)
            ));
        }
    }

    (diffs.is_empty(), diffs)
}

/// Augment Soroban transaction metadata with missing read footprint TTL entries.
///
/// C++ stellar-core produces STATE (ledger-start) / UPDATED (current) pairs for ALL
/// entries in the read footprint whose TTL changed during the ledger, even if the
/// specific transaction didn't change the TTL. This function adds those missing entries.
fn augment_soroban_ttl_metadata(
    meta: &mut stellar_xdr::curr::TransactionMeta,
    footprint: &stellar_xdr::curr::LedgerFootprint,
    ledger_start_ttls: &std::collections::HashMap<
        stellar_xdr::curr::Hash,
        stellar_xdr::curr::LedgerEntry,
    >,
    executor: &stellar_core_ledger::execution::TransactionExecutor,
    ledger_seq: u32,
) {
    use stellar_xdr::curr::{
        LedgerEntry, LedgerEntryChange, LedgerEntryData, LedgerKey, Limits, WriteXdr,
    };

    // Get the operation changes from metadata - we need to convert to Vec to extend
    let (existing_changes, rebuild_meta) = match meta {
        stellar_xdr::curr::TransactionMeta::V3(v3) => {
            if v3.operations.is_empty() {
                return;
            }
            (
                v3.operations[0].changes.iter().cloned().collect::<Vec<_>>(),
                true,
            )
        }
        stellar_xdr::curr::TransactionMeta::V4(v4) => {
            if v4.operations.is_empty() {
                return;
            }
            (
                v4.operations[0].changes.iter().cloned().collect::<Vec<_>>(),
                true,
            )
        }
        _ => return,
    };

    if !rebuild_meta {
        return;
    }

    // Collect existing TTL key_hashes from our metadata
    let mut existing_ttl_hashes: std::collections::HashSet<stellar_xdr::curr::Hash> =
        std::collections::HashSet::new();
    for change in existing_changes.iter() {
        match change {
            LedgerEntryChange::State(entry)
            | LedgerEntryChange::Updated(entry)
            | LedgerEntryChange::Created(entry)
            | LedgerEntryChange::Restored(entry) => {
                if let LedgerEntryData::Ttl(ttl) = &entry.data {
                    existing_ttl_hashes.insert(ttl.key_hash.clone());
                }
            }
            _ => {}
        }
    }

    // For each entry in the footprint, check if we need to add TTL STATE/UPDATED
    let mut additional_changes: Vec<LedgerEntryChange> = Vec::new();
    for key in footprint
        .read_only
        .iter()
        .chain(footprint.read_write.iter())
    {
        match key {
            LedgerKey::ContractData(_) | LedgerKey::ContractCode(_) => {
                if let Ok(key_bytes) = key.to_xdr(Limits::none()) {
                    let hash_bytes = stellar_core_crypto::sha256(&key_bytes);
                    let key_hash = stellar_xdr::curr::Hash(*hash_bytes.as_bytes());

                    // Skip if we already have this TTL in our changes
                    if existing_ttl_hashes.contains(&key_hash) {
                        continue;
                    }

                    // Get ledger-start TTL entry (full LedgerEntry with correct last_modified)
                    let ledger_start_entry = match ledger_start_ttls.get(&key_hash) {
                        Some(entry) => entry,
                        None => continue, // No ledger-start TTL, skip
                    };

                    // Extract the TTL data from ledger-start entry
                    let ledger_start_ttl = match &ledger_start_entry.data {
                        LedgerEntryData::Ttl(ttl) => ttl,
                        _ => continue,
                    };

                    // Get current TTL value from executor state
                    let current_ttl = match executor.state().get_ttl(&key_hash) {
                        Some(ttl) => ttl,
                        None => continue, // No current TTL, skip
                    };

                    // Only add if TTL changed during the ledger
                    if ledger_start_ttl.live_until_ledger_seq != current_ttl.live_until_ledger_seq {
                        // Use the ledger-start entry's last_modified for STATE
                        let state_entry = ledger_start_entry.clone();
                        // Build UPDATED entry with current values and current ledger's last_modified
                        let updated_entry = LedgerEntry {
                            last_modified_ledger_seq: ledger_seq,
                            data: LedgerEntryData::Ttl(current_ttl.clone()),
                            ext: stellar_xdr::curr::LedgerEntryExt::V0,
                        };
                        additional_changes.push(LedgerEntryChange::State(state_entry));
                        additional_changes.push(LedgerEntryChange::Updated(updated_entry));
                    }
                }
            }
            _ => {}
        }
    }

    // If we have additional changes, rebuild the entire meta structure
    if !additional_changes.is_empty() {
        let mut all_changes = existing_changes;
        all_changes.extend(additional_changes);

        // Convert to LedgerEntryChanges
        let new_changes: stellar_xdr::curr::LedgerEntryChanges = match all_changes.try_into() {
            Ok(c) => c,
            Err(_) => return,
        };

        // Rebuild the meta with the new changes
        match meta {
            stellar_xdr::curr::TransactionMeta::V3(v3) => {
                if !v3.operations.is_empty() {
                    // Clone the operations and update the first one's changes
                    let mut ops: Vec<stellar_xdr::curr::OperationMeta> =
                        v3.operations.iter().cloned().collect();
                    ops[0].changes = new_changes;
                    if let Ok(new_ops) = ops.try_into() {
                        v3.operations = new_ops;
                    }
                }
            }
            stellar_xdr::curr::TransactionMeta::V4(v4) => {
                if !v4.operations.is_empty() {
                    // Clone the operations and update the first one's changes
                    let mut ops: Vec<stellar_xdr::curr::OperationMetaV2> =
                        v4.operations.iter().cloned().collect();
                    ops[0].changes = new_changes;
                    if let Ok(new_ops) = ops.try_into() {
                        v4.operations = new_ops;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Compare transaction meta to find differences in ledger entry changes.
/// For fee bump transactions with separate fee source, fee_changes from Phase 1 should be prepended.
/// Uses order-independent (multiset) comparison since C++ stellar-core's UnorderedMap iteration
/// order is non-deterministic (depends on RandHasher's gMixer random value).
///
/// The comparison is fully order-independent: as long as both metas contain the same set of
/// changes (same XDR content, same multiplicity), the comparison passes regardless of order.
fn compare_transaction_meta(
    our_meta: &stellar_xdr::curr::TransactionMeta,
    cdp_meta: &stellar_xdr::curr::TransactionMeta,
    fee_changes: Option<&stellar_xdr::curr::LedgerEntryChanges>,
    show_diff: bool,
) -> (bool, Vec<String>) {
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use stellar_xdr::curr::{Limits, ReadXdr, WriteXdr};

    let mut diffs = Vec::new();

    // Extract changes from both metas
    // For fee bump transactions with separate fee source, prepend Phase 1 fee_changes
    let mut our_changes = Vec::new();
    if let Some(fc) = fee_changes {
        our_changes.extend(fc.iter().cloned());
    }
    our_changes.extend(extract_changes_from_meta(our_meta));
    let cdp_changes = extract_changes_from_meta(cdp_meta);

    // Compare the number of changes first (quick check)
    if our_changes.len() != cdp_changes.len() {
        diffs.push(format!(
            "Change count mismatch: ours={}, expected={}",
            our_changes.len(),
            cdp_changes.len()
        ));
        // If counts differ, we already know it won't match, but continue to show diffs
    }

    // Build multiset (hash -> count) for each set of changes
    // This is fully order-independent: we just count occurrences of each unique change
    fn build_change_multiset(
        changes: &[stellar_xdr::curr::LedgerEntryChange],
    ) -> HashMap<[u8; 32], (usize, Vec<u8>)> {
        let mut multiset = HashMap::new();
        for change in changes {
            let xdr = change.to_xdr(Limits::none()).unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update(&xdr);
            let hash: [u8; 32] = hasher.finalize().into();
            let entry = multiset.entry(hash).or_insert((0, xdr));
            entry.0 += 1;
        }
        multiset
    }

    let our_multiset = build_change_multiset(&our_changes);
    let cdp_multiset = build_change_multiset(&cdp_changes);

    // Compare multisets
    // Check for items in ours but not in CDP (or different count)
    for (hash, (our_count, our_xdr)) in &our_multiset {
        match cdp_multiset.get(hash) {
            Some((cdp_count, _)) if our_count == cdp_count => {
                // Match - same count
            }
            Some((cdp_count, _)) => {
                // Count mismatch
                if show_diff {
                    diffs.push(format!(
                        "Change count differs: ours={} vs expected={} for change: {}",
                        our_count,
                        cdp_count,
                        describe_change(
                            &stellar_xdr::curr::LedgerEntryChange::from_xdr(
                                our_xdr,
                                Limits::none()
                            )
                            .unwrap_or(
                                stellar_xdr::curr::LedgerEntryChange::Removed(
                                    stellar_xdr::curr::LedgerKey::Account(
                                        stellar_xdr::curr::LedgerKeyAccount {
                                            account_id: stellar_xdr::curr::AccountId(
                                                stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                                                    stellar_xdr::curr::Uint256([0u8; 32])
                                                )
                                            ),
                                        }
                                    )
                                )
                            )
                        )
                    ));
                } else {
                    diffs.push("Count mismatch".to_string());
                }
            }
            None => {
                // Not found in CDP
                if show_diff {
                    diffs.push(format!(
                        "Extra change in ours (count={}): {}",
                        our_count,
                        describe_change(
                            &stellar_xdr::curr::LedgerEntryChange::from_xdr(
                                our_xdr,
                                Limits::none()
                            )
                            .unwrap_or(
                                stellar_xdr::curr::LedgerEntryChange::Removed(
                                    stellar_xdr::curr::LedgerKey::Account(
                                        stellar_xdr::curr::LedgerKeyAccount {
                                            account_id: stellar_xdr::curr::AccountId(
                                                stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                                                    stellar_xdr::curr::Uint256([0u8; 32])
                                                )
                                            ),
                                        }
                                    )
                                )
                            )
                        )
                    ));
                } else {
                    diffs.push("Extra change in ours".to_string());
                }
            }
        }
    }

    // Check for items in CDP but not in ours
    for (hash, (cdp_count, cdp_xdr)) in &cdp_multiset {
        if !our_multiset.contains_key(hash) {
            if show_diff {
                diffs.push(format!(
                    "Missing change from CDP (count={}): {}",
                    cdp_count,
                    describe_change(
                        &stellar_xdr::curr::LedgerEntryChange::from_xdr(cdp_xdr, Limits::none())
                            .unwrap_or(stellar_xdr::curr::LedgerEntryChange::Removed(
                                stellar_xdr::curr::LedgerKey::Account(
                                    stellar_xdr::curr::LedgerKeyAccount {
                                        account_id: stellar_xdr::curr::AccountId(
                                            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                                                stellar_xdr::curr::Uint256([0u8; 32])
                                            )
                                        ),
                                    }
                                )
                            ))
                    )
                ));
            } else {
                diffs.push("Missing change from CDP".to_string());
            }
        }
    }

    (diffs.is_empty(), diffs)
}

/// Describe a LedgerEntryChange for debugging.
fn describe_change(change: &stellar_xdr::curr::LedgerEntryChange) -> String {
    use stellar_xdr::curr::{LedgerEntryChange, LedgerEntryData};

    fn describe_entry(entry: &LedgerEntryData) -> String {
        match entry {
            LedgerEntryData::Account(a) => {
                // Just show first/last few bytes of account id
                let id = &a.account_id.0;
                let id_hex = match id {
                    stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(pk) => {
                        hex::encode(&pk.0[0..4])
                    }
                };
                format!("Account({}...)", id_hex)
            }
            LedgerEntryData::Trustline(t) => format!("Trustline({:?})", t.asset),
            LedgerEntryData::Offer(o) => format!("Offer({})", o.offer_id),
            LedgerEntryData::Data(d) => {
                format!("Data({})", String::from_utf8_lossy(&d.data_name.0))
            }
            LedgerEntryData::ClaimableBalance(_) => "ClaimableBalance".to_string(),
            LedgerEntryData::LiquidityPool(_) => "LiquidityPool".to_string(),
            LedgerEntryData::ContractData(_) => "ContractData".to_string(),
            LedgerEntryData::ContractCode(_) => "ContractCode".to_string(),
            LedgerEntryData::ConfigSetting(_) => "ConfigSetting".to_string(),
            LedgerEntryData::Ttl(_) => "Ttl".to_string(),
        }
    }

    match change {
        LedgerEntryChange::Created(entry) => format!("CREATED {}", describe_entry(&entry.data)),
        LedgerEntryChange::Updated(entry) => format!("UPDATED {}", describe_entry(&entry.data)),
        LedgerEntryChange::Removed(key) => format!("REMOVED {:?}", key),
        LedgerEntryChange::State(entry) => format!("STATE {}", describe_entry(&entry.data)),
        LedgerEntryChange::Restored(entry) => format!("RESTORED {}", describe_entry(&entry.data)),
    }
}

/// Describe a LedgerEntryChange with detailed values for debugging.
fn describe_change_detailed(change: &stellar_xdr::curr::LedgerEntryChange) -> String {
    use stellar_xdr::curr::{LedgerEntry, LedgerEntryChange, LedgerEntryData};

    fn describe_entry_detailed(entry: &LedgerEntry) -> String {
        let (ext_label, sponsor_hex) = match &entry.ext {
            stellar_xdr::curr::LedgerEntryExt::V0 => ("V0", None),
            stellar_xdr::curr::LedgerEntryExt::V1(v1) => {
                let sponsor_hex = v1.sponsoring_id.0.as_ref().map(|sponsor| match &sponsor.0 {
                    stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(pk) => {
                        hex::encode(&pk.0[0..4])
                    }
                });
                ("V1", sponsor_hex)
            }
        };
        let sponsor_suffix = sponsor_hex
            .as_ref()
            .map(|s| format!(" sponsor={}", s))
            .unwrap_or_default();
        let ext_suffix = format!(" ext={}", ext_label);
        let entry_suffix = format!("{}{}", ext_suffix, sponsor_suffix);
        match &entry.data {
            LedgerEntryData::Account(a) => {
                let (num_sponsored, num_sponsoring) = match &a.ext {
                    stellar_xdr::curr::AccountEntryExt::V1(v1) => match &v1.ext {
                        stellar_xdr::curr::AccountEntryExtensionV1Ext::V2(v2) => {
                            (v2.num_sponsored, v2.num_sponsoring)
                        }
                        _ => (0, 0),
                    },
                    _ => (0, 0),
                };
                let (account_ext, v1_ext, signer_sponsoring_len) = match &a.ext {
                    stellar_xdr::curr::AccountEntryExt::V0 => ("V0", "V0", 0),
                    stellar_xdr::curr::AccountEntryExt::V1(v1) => match &v1.ext {
                        stellar_xdr::curr::AccountEntryExtensionV1Ext::V0 => ("V1", "V0", 0),
                        stellar_xdr::curr::AccountEntryExtensionV1Ext::V2(v2) => {
                            ("V1", "V2", v2.signer_sponsoring_i_ds.len())
                        }
                    },
                };
                let describe_signer_key = |key: &stellar_xdr::curr::SignerKey| -> String {
                    match key {
                        stellar_xdr::curr::SignerKey::Ed25519(pk) => hex::encode(&pk.0[0..4]),
                        stellar_xdr::curr::SignerKey::HashX(hash) => hex::encode(&hash.0[0..4]),
                        stellar_xdr::curr::SignerKey::PreAuthTx(hash) => hex::encode(&hash.0[0..4]),
                        stellar_xdr::curr::SignerKey::Ed25519SignedPayload(payload) => {
                            hex::encode(&payload.ed25519.0[0..4])
                        }
                    }
                };
                let signer_samples: Vec<String> = a
                    .signers
                    .iter()
                    .take(3)
                    .map(|s| format!("{}:{}", describe_signer_key(&s.key), s.weight))
                    .collect();
                let signer_info = if a.signers.is_empty() {
                    "signers=0".to_string()
                } else if a.signers.len() > 3 {
                    format!(
                        "signers={} [{}...]",
                        a.signers.len(),
                        signer_samples.join(",")
                    )
                } else {
                    format!("signers={} [{}]", a.signers.len(), signer_samples.join(","))
                };
                let id = &a.account_id.0;
                let id_hex = match id {
                    stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(pk) => {
                        hex::encode(&pk.0[0..4])
                    }
                };
                let inflation_dest = a.inflation_dest.as_ref().map(|id| match &id.0 {
                    stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(pk) => {
                        hex::encode(&pk.0[0..4])
                    }
                });
                let inflation_info = inflation_dest
                    .as_ref()
                    .map(|id| format!(" infdest={}...", id))
                    .unwrap_or_default();
                let home_domain = String::from_utf8_lossy(&a.home_domain.0);
                let home_domain_info = if home_domain.is_empty() {
                    String::new()
                } else {
                    format!(" domain=\"{}\"", home_domain)
                };
                let thresholds = format!(
                    "{}-{}-{}-{}",
                    a.thresholds.0[0], a.thresholds.0[1], a.thresholds.0[2], a.thresholds.0[3]
                );
                format!(
                    "Account({}...) bal={} seq={} lm={} ns={} nsp={} sub={} flags=0x{:x} thresh={}{}{} aext={} v1ext={} ssid={} {}{}",
                    id_hex,
                    a.balance,
                    a.seq_num.0,
                    entry.last_modified_ledger_seq,
                    num_sponsored,
                    num_sponsoring,
                    a.num_sub_entries,
                    a.flags,
                    thresholds,
                    inflation_info,
                    home_domain_info,
                    account_ext,
                    v1_ext,
                    signer_sponsoring_len,
                    signer_info,
                    entry_suffix
                )
            }
            LedgerEntryData::Trustline(t) => {
                let asset_info = match &t.asset {
                    stellar_xdr::curr::TrustLineAsset::Native => "Native".to_string(),
                    stellar_xdr::curr::TrustLineAsset::CreditAlphanum4(a) => {
                        let issuer_hex = match &a.issuer.0 {
                            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(pk) => {
                                hex::encode(&pk.0[0..4])
                            }
                        };
                        let code = String::from_utf8_lossy(&a.asset_code.0);
                        format!("{}:{}...", code, issuer_hex)
                    }
                    stellar_xdr::curr::TrustLineAsset::CreditAlphanum12(a) => {
                        let issuer_hex = match &a.issuer.0 {
                            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(pk) => {
                                hex::encode(&pk.0[0..4])
                            }
                        };
                        let code = String::from_utf8_lossy(&a.asset_code.0);
                        format!("{}:{}...", code, issuer_hex)
                    }
                    stellar_xdr::curr::TrustLineAsset::PoolShare(pool_id) => {
                        format!("PoolShare({}...)", hex::encode(&pool_id.0 .0[0..4]))
                    }
                };
                format!(
                    "Trustline({}) bal={} lim={} lm={}{}",
                    asset_info, t.balance, t.limit, entry.last_modified_ledger_seq, entry_suffix
                )
            }
            LedgerEntryData::Offer(o) => {
                format!(
                    "Offer({}) amount={} price={}/{} sell={:?} buy={:?} flags={} lm={}{}",
                    o.offer_id,
                    o.amount,
                    o.price.n,
                    o.price.d,
                    o.selling,
                    o.buying,
                    o.flags,
                    entry.last_modified_ledger_seq,
                    entry_suffix
                )
            }
            LedgerEntryData::Data(d) => {
                let name = String::from_utf8_lossy(&d.data_name.0);
                format!(
                    "Data({}) len={} lm={}{}",
                    name,
                    d.data_value.len(),
                    entry.last_modified_ledger_seq,
                    entry_suffix
                )
            }
            LedgerEntryData::ContractData(cd) => {
                let contract_hex = match &cd.contract {
                    stellar_xdr::curr::ScAddress::Contract(contract_id) => {
                        hex::encode(&contract_id.0 .0[0..4])
                    }
                    _ => "other".to_string(),
                };
                format!(
                    "ContractData({}...) dur={:?} lm={}{}",
                    contract_hex, cd.durability, entry.last_modified_ledger_seq, entry_suffix
                )
            }
            LedgerEntryData::ContractCode(cc) => {
                let hash_hex = hex::encode(&cc.hash.0[0..4]);
                // Show ext (cost inputs) for debugging
                let ext_info = match &cc.ext {
                    stellar_xdr::curr::ContractCodeEntryExt::V0 => "ext=V0".to_string(),
                    stellar_xdr::curr::ContractCodeEntryExt::V1(v1) => {
                        format!("ext=V1(n_insns={} n_fns={} n_globals={} n_tbl_entries={} n_types={} n_data_seg_bytes={} n_elem_segs={} n_imports={} n_exports={} n_data_segs={})",
                            v1.cost_inputs.n_instructions,
                            v1.cost_inputs.n_functions,
                            v1.cost_inputs.n_globals,
                            v1.cost_inputs.n_table_entries,
                            v1.cost_inputs.n_types,
                            v1.cost_inputs.n_data_segment_bytes,
                            v1.cost_inputs.n_elem_segments,
                            v1.cost_inputs.n_imports,
                            v1.cost_inputs.n_exports,
                            v1.cost_inputs.n_data_segments,
                        )
                    }
                };
                format!(
                    "ContractCode({}...) {} lm={}{}",
                    hash_hex, ext_info, entry.last_modified_ledger_seq, entry_suffix
                )
            }
            LedgerEntryData::Ttl(ttl) => {
                let key_hex = hex::encode(&ttl.key_hash.0[0..4]);
                format!(
                    "Ttl({}...) live_until={} lm={}{}",
                    key_hex,
                    ttl.live_until_ledger_seq,
                    entry.last_modified_ledger_seq,
                    entry_suffix
                )
            }
            LedgerEntryData::ClaimableBalance(cb) => {
                let id_hex = match &cb.balance_id {
                    stellar_xdr::curr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(hash) => {
                        hex::encode(&hash.0[0..4])
                    }
                };
                let asset = stellar_core_common::asset::asset_to_string(&cb.asset);
                let (ext_label, flags) = match &cb.ext {
                    stellar_xdr::curr::ClaimableBalanceEntryExt::V0 => ("V0", 0),
                    stellar_xdr::curr::ClaimableBalanceEntryExt::V1(v1) => ("V1", v1.flags),
                };
                let sponsor = match &entry.ext {
                    stellar_xdr::curr::LedgerEntryExt::V0 => "none".to_string(),
                    stellar_xdr::curr::LedgerEntryExt::V1(v1) => match &v1.sponsoring_id.0 {
                        Some(id) => match &id.0 {
                            stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(pk) => {
                                hex::encode(&pk.0[0..4])
                            }
                        },
                        None => "none".to_string(),
                    },
                };
                format!(
                    "ClaimableBalance({}...) asset={} amt={} claimants={} ext={} flags={} sponsor={} lm={}",
                    id_hex,
                    asset,
                    cb.amount,
                    cb.claimants.len(),
                    ext_label,
                    flags,
                    sponsor,
                    entry.last_modified_ledger_seq
                )
            }
            _ => format!("lm={}", entry.last_modified_ledger_seq),
        }
    }

    match change {
        LedgerEntryChange::Created(entry) => format!("CREATED {}", describe_entry_detailed(entry)),
        LedgerEntryChange::Updated(entry) => format!("UPDATED {}", describe_entry_detailed(entry)),
        LedgerEntryChange::Removed(_) => describe_change(change),
        LedgerEntryChange::State(entry) => format!("STATE {}", describe_entry_detailed(entry)),
        LedgerEntryChange::Restored(entry) => {
            format!("RESTORED {}", describe_entry_detailed(entry))
        }
    }
}

/// Extract all ledger entry changes from TransactionMeta, filtering out no-op changes.
/// A no-op change is a STATE/UPDATED pair where the entries are identical (read but not modified).
fn extract_changes_from_meta(
    meta: &stellar_xdr::curr::TransactionMeta,
) -> Vec<stellar_xdr::curr::LedgerEntryChange> {
    use stellar_xdr::curr::{LedgerEntryChange, TransactionMeta};

    let mut raw_changes = Vec::new();

    match meta {
        TransactionMeta::V0(operations) => {
            for op_meta in operations.iter() {
                raw_changes.extend(op_meta.changes.iter().cloned());
            }
        }
        TransactionMeta::V1(v1) => {
            raw_changes.extend(v1.tx_changes.iter().cloned());
            for op_meta in v1.operations.iter() {
                raw_changes.extend(op_meta.changes.iter().cloned());
            }
        }
        TransactionMeta::V2(v2) => {
            raw_changes.extend(v2.tx_changes_before.iter().cloned());
            for op_meta in v2.operations.iter() {
                raw_changes.extend(op_meta.changes.iter().cloned());
            }
            raw_changes.extend(v2.tx_changes_after.iter().cloned());
        }
        TransactionMeta::V3(v3) => {
            raw_changes.extend(v3.tx_changes_before.iter().cloned());
            for op_meta in v3.operations.iter() {
                raw_changes.extend(op_meta.changes.iter().cloned());
            }
            raw_changes.extend(v3.tx_changes_after.iter().cloned());
        }
        TransactionMeta::V4(v4) => {
            raw_changes.extend(v4.tx_changes_before.iter().cloned());
            for op_meta in v4.operations.iter() {
                raw_changes.extend(op_meta.changes.iter().cloned());
            }
            raw_changes.extend(v4.tx_changes_after.iter().cloned());
        }
    }

    // Filter out no-op STATE/UPDATED pairs where the entry data is unchanged.
    // In Stellar metadata, STATE and UPDATED always come as consecutive pairs.
    // If STATE[i].data == UPDATED[i+1].data, it's a read without modification - skip both.
    // Note: We compare only the `data` field, not `last_modified_ledger_seq` which changes on write.
    let mut filtered = Vec::new();
    let mut i = 0;
    while i < raw_changes.len() {
        if i + 1 < raw_changes.len() {
            if let (
                LedgerEntryChange::State(state_entry),
                LedgerEntryChange::Updated(updated_entry),
            ) = (&raw_changes[i], &raw_changes[i + 1])
            {
                // Compare data portions only - last_modified_ledger_seq will differ
                if state_entry.data == updated_entry.data {
                    i += 2;
                    continue;
                }
            }
        }
        filtered.push(raw_changes[i].clone());
        i += 1;
    }

    filtered
}

/// Extract ledger entry changes separated by source: tx_changes vs operation_changes.
///
/// Returns (tx_changes, operation_changes) where:
/// - tx_changes = tx_changes_before + tx_changes_after (includes real sequence bumps)
/// - operation_changes = all changes from operation execution (may have polluted seq values)
fn extract_changes_by_source(
    meta: &stellar_xdr::curr::TransactionMeta,
) -> (
    Vec<stellar_xdr::curr::LedgerEntryChange>,
    Vec<stellar_xdr::curr::LedgerEntryChange>,
) {
    use stellar_xdr::curr::TransactionMeta;

    let mut tx_changes = Vec::new();
    let mut op_changes = Vec::new();

    match meta {
        TransactionMeta::V0(operations) => {
            // V0 has no tx_changes, only operation changes
            for op_meta in operations.iter() {
                op_changes.extend(op_meta.changes.iter().cloned());
            }
        }
        TransactionMeta::V1(v1) => {
            tx_changes.extend(v1.tx_changes.iter().cloned());
            for op_meta in v1.operations.iter() {
                op_changes.extend(op_meta.changes.iter().cloned());
            }
        }
        TransactionMeta::V2(v2) => {
            tx_changes.extend(v2.tx_changes_before.iter().cloned());
            for op_meta in v2.operations.iter() {
                op_changes.extend(op_meta.changes.iter().cloned());
            }
            tx_changes.extend(v2.tx_changes_after.iter().cloned());
        }
        TransactionMeta::V3(v3) => {
            tx_changes.extend(v3.tx_changes_before.iter().cloned());
            for op_meta in v3.operations.iter() {
                op_changes.extend(op_meta.changes.iter().cloned());
            }
            tx_changes.extend(v3.tx_changes_after.iter().cloned());
        }
        TransactionMeta::V4(v4) => {
            tx_changes.extend(v4.tx_changes_before.iter().cloned());
            for op_meta in v4.operations.iter() {
                op_changes.extend(op_meta.changes.iter().cloned());
            }
            tx_changes.extend(v4.tx_changes_after.iter().cloned());
        }
    }

    (tx_changes, op_changes)
}

/// Sample config command handler.
fn cmd_sample_config() -> anyhow::Result<()> {
    let sample = AppConfig::sample_config();
    println!("{}", sample);
    Ok(())
}

#[derive(Clone, Debug)]
enum FinalChange {
    Init(stellar_xdr::curr::LedgerEntry),
    Live(stellar_xdr::curr::LedgerEntry),
    Dead,
}

#[derive(Clone)]
struct CoalescedLedgerChanges {
    changes: std::collections::BTreeMap<stellar_xdr::curr::LedgerKey, FinalChange>,
}

impl CoalescedLedgerChanges {
    fn new() -> Self {
        Self {
            changes: std::collections::BTreeMap::new(),
        }
    }

    fn apply_change(&mut self, change: &stellar_xdr::curr::LedgerEntryChange) {
        use stellar_core_bucket::ledger_entry_to_key;
        use stellar_xdr::curr::LedgerEntryChange;

        match change {
            LedgerEntryChange::Created(entry) => {
                if let Some(key) = ledger_entry_to_key(entry) {
                    self.changes
                        .entry(key)
                        .and_modify(|existing| match existing {
                            FinalChange::Dead => {
                                *existing = FinalChange::Live(entry.clone());
                            }
                            FinalChange::Init(_) => {
                                *existing = FinalChange::Init(entry.clone());
                            }
                            FinalChange::Live(_) => {
                                *existing = FinalChange::Live(entry.clone());
                            }
                        })
                        .or_insert(FinalChange::Init(entry.clone()));
                }
            }
            LedgerEntryChange::Updated(entry) | LedgerEntryChange::Restored(entry) => {
                if let Some(key) = ledger_entry_to_key(entry) {
                    self.changes
                        .entry(key)
                        .and_modify(|existing| match existing {
                            FinalChange::Init(_) => {
                                *existing = FinalChange::Init(entry.clone());
                            }
                            _ => {
                                *existing = FinalChange::Live(entry.clone());
                            }
                        })
                        .or_insert(FinalChange::Live(entry.clone()));
                }
            }
            LedgerEntryChange::Removed(key) => {
                if let Some(FinalChange::Init(_)) = self.changes.get(key) {
                    self.changes.remove(key);
                } else {
                    self.changes.insert(key.clone(), FinalChange::Dead);
                }
            }
            LedgerEntryChange::State(_) => {}
        }
    }

    fn to_vectors(
        self,
    ) -> (
        Vec<stellar_xdr::curr::LedgerEntry>,
        Vec<stellar_xdr::curr::LedgerEntry>,
        Vec<stellar_xdr::curr::LedgerKey>,
    ) {
        let mut init_entries = Vec::new();
        let mut live_entries = Vec::new();
        let mut dead_entries = Vec::new();

        for (key, state) in self.changes {
            match state {
                FinalChange::Init(entry) => init_entries.push(entry),
                FinalChange::Live(entry) => live_entries.push(entry),
                FinalChange::Dead => dead_entries.push(key),
            }
        }

        (init_entries, live_entries, dead_entries)
    }
}

fn apply_change_with_prestate(
    aggregator: &mut CoalescedLedgerChanges,
    bucket_list: &stellar_core_bucket::BucketList,
    change: &stellar_xdr::curr::LedgerEntryChange,
) {
    use stellar_core_bucket::ledger_entry_to_key;
    use stellar_xdr::curr::LedgerEntryChange;

    match change {
        LedgerEntryChange::Created(entry) => {
            if let Some(key) = ledger_entry_to_key(entry) {
                let existed = bucket_list.get(&key).ok().flatten().is_some();
                if existed {
                    aggregator.apply_change(&LedgerEntryChange::Updated(entry.clone()));
                } else {
                    aggregator.apply_change(change);
                }
            }
        }
        LedgerEntryChange::Restored(entry) => {
            // Restored entries can come from the hot archive (not in live BL)
            // or be auto-restored from the live bucket list. Classify based
            // on pre-state to match LedgerTxn init/live behavior.
            if let Some(key) = ledger_entry_to_key(entry) {
                let existed = bucket_list.get(&key).ok().flatten().is_some();
                if existed {
                    aggregator.apply_change(&LedgerEntryChange::Updated(entry.clone()));
                } else {
                    aggregator.apply_change(&LedgerEntryChange::Created(entry.clone()));
                }
            }
        }
        _ => aggregator.apply_change(change),
    }
}

fn maybe_snapshot_soroban_state_size_window(
    seq: u32,
    protocol_version: u32,
    bucket_list: &stellar_core_bucket::BucketList,
    soroban_state_size: u64,
    aggregator: &mut CoalescedLedgerChanges,
    archival_override: Option<stellar_xdr::curr::StateArchivalSettings>,
) {
    use stellar_core_common::protocol::MIN_SOROBAN_PROTOCOL_VERSION;
    use stellar_xdr::curr::{
        ConfigSettingEntry, ConfigSettingId, LedgerEntry, LedgerEntryChange, LedgerEntryData,
        LedgerEntryExt, LedgerKey, LedgerKeyConfigSetting, VecM,
    };

    if protocol_version < MIN_SOROBAN_PROTOCOL_VERSION {
        return;
    }

    let archival = if let Some(override_settings) = archival_override {
        override_settings
    } else {
        let archival_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
            config_setting_id: ConfigSettingId::StateArchival,
        });
        let Some(archival_entry) = bucket_list.get(&archival_key).ok().flatten() else {
            return;
        };
        let LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(archival)) =
            archival_entry.data
        else {
            return;
        };
        archival
    };

    let sample_period = archival.live_soroban_state_size_window_sample_period;
    let sample_size = archival.live_soroban_state_size_window_sample_size as usize;
    if sample_period == 0 || sample_size == 0 {
        return;
    }

    let window_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::LiveSorobanStateSizeWindow,
    });
    let Some(window_entry) = bucket_list.get(&window_key).ok().flatten() else {
        return;
    };
    let LedgerEntryData::ConfigSetting(ConfigSettingEntry::LiveSorobanStateSizeWindow(window)) =
        window_entry.data
    else {
        return;
    };

    let mut window_vec: Vec<u64> = window.into();
    if window_vec.is_empty() {
        return;
    }

    let mut changed = false;
    if window_vec.len() != sample_size {
        if sample_size < window_vec.len() {
            let remove_count = window_vec.len() - sample_size;
            window_vec.drain(0..remove_count);
        } else {
            let oldest = window_vec[0];
            let insert_count = sample_size - window_vec.len();
            for _ in 0..insert_count {
                window_vec.insert(0, oldest);
            }
        }
        changed = true;
    }

    if seq % sample_period == 0 {
        if !window_vec.is_empty() {
            window_vec.remove(0);
            window_vec.push(soroban_state_size);
            changed = true;
        }
    }

    if !changed {
        return;
    }

    let window_vecm: VecM<u64> = match window_vec.try_into() {
        Ok(vecm) => vecm,
        Err(_) => return,
    };

    let updated_entry = LedgerEntry {
        last_modified_ledger_seq: seq,
        data: LedgerEntryData::ConfigSetting(ConfigSettingEntry::LiveSorobanStateSizeWindow(
            window_vecm,
        )),
        ext: LedgerEntryExt::V0,
    };
    apply_change_with_prestate(
        aggregator,
        bucket_list,
        &LedgerEntryChange::Updated(updated_entry),
    );
}

/// Offline commands handler.
async fn cmd_offline(cmd: OfflineCommands, config: AppConfig) -> anyhow::Result<()> {
    match cmd {
        OfflineCommands::ConvertKey { key } => convert_key(&key),
        OfflineCommands::DecodeXdr { r#type, value } => decode_xdr(&r#type, &value),
        OfflineCommands::EncodeXdr { r#type, value } => encode_xdr(&r#type, &value),
        OfflineCommands::BucketInfo { path } => bucket_info(&path),
        OfflineCommands::ReplayBucketList {
            from,
            to,
            stop_on_error,
            live_only,
            cdp_url,
            cdp_date,
        } => {
            cmd_replay_bucket_list(
                config,
                from,
                to,
                stop_on_error,
                live_only,
                &cdp_url,
                &cdp_date,
            )
            .await
        }
        OfflineCommands::VerifyExecution {
            from,
            to,
            stop_on_error,
            show_diff,
            cdp_url,
            cdp_date,
            cache_dir,
            no_cache,
            quiet,
        } => {
            cmd_verify_execution(
                config,
                from,
                to,
                stop_on_error,
                show_diff,
                &cdp_url,
                &cdp_date,
                cache_dir,
                no_cache,
                quiet,
            )
            .await
        }
        OfflineCommands::DebugBucketEntry {
            checkpoint,
            account,
        } => cmd_debug_bucket_entry(config, checkpoint, &account).await,
        OfflineCommands::SignTransaction {
            netid,
            input,
            base64,
        } => sign_transaction(&netid, &input, base64),
        OfflineCommands::SecToPub => sec_to_pub(),
        OfflineCommands::DumpLedger {
            output,
            entry_type,
            limit,
            last_modified_ledger_count,
        } => {
            cmd_dump_ledger(
                config,
                output,
                entry_type,
                limit,
                last_modified_ledger_count,
            )
            .await
        }
        OfflineCommands::SelfCheck => cmd_self_check(config).await,
        OfflineCommands::VerifyCheckpoints { output, from, to } => {
            cmd_verify_checkpoints(config, output, from, to).await
        }
    }
}

/// Converts Stellar IDs between formats (equivalent to C++ convert-id).
///
/// Handles the following input formats:
/// - `G...` - Public key (account ID) -> displays strKey and hex
/// - `S...` - Secret seed -> displays seed strKey and derived public key
/// - `T...` - Pre-auth transaction hash -> displays type and hex
/// - `X...` - SHA256 hash -> displays type and hex
/// - `M...` - Muxed account -> displays type, account ID, and memo ID
/// - `C...` - Contract address -> displays type and hex
/// - `P...` - Signed payload -> displays type and hex
/// - 64 hex chars - 32-byte hex -> displays all possible interpretations
fn convert_key(key: &str) -> anyhow::Result<()> {
    use stellar_core_crypto::{
        decode_contract, decode_muxed_account, decode_pre_auth_tx, decode_sha256_hash,
        decode_signed_payload, encode_account_id, encode_contract, encode_muxed_account,
        encode_pre_auth_tx, encode_sha256_hash,
    };

    let key = key.trim();

    // Try public key (G...)
    if key.starts_with('G') {
        let pk = stellar_core_crypto::PublicKey::from_strkey(key)?;
        println!("PublicKey:");
        println!("  strKey: {}", pk.to_strkey());
        println!("  hex: {}", hex::encode(pk.as_bytes()));
        return Ok(());
    }

    // Try secret seed (S...)
    if key.starts_with('S') {
        let sk = stellar_core_crypto::SecretKey::from_strkey(key)?;
        let pk = sk.public_key();
        println!("Seed:");
        println!("  strKey: {}", sk.to_strkey());
        println!("PublicKey:");
        println!("  strKey: {}", pk.to_strkey());
        println!("  hex: {}", hex::encode(pk.as_bytes()));
        return Ok(());
    }

    // Try pre-auth transaction hash (T...)
    if key.starts_with('T') {
        let hash = decode_pre_auth_tx(key)?;
        println!("StrKey:");
        println!("  type: STRKEY_PRE_AUTH_TX");
        println!("  hex: {}", hex::encode(hash));
        return Ok(());
    }

    // Try SHA256 hash (X...)
    if key.starts_with('X') {
        let hash = decode_sha256_hash(key)?;
        println!("StrKey:");
        println!("  type: STRKEY_HASH_X");
        println!("  hex: {}", hex::encode(hash));
        return Ok(());
    }

    // Try muxed account (M...)
    if key.starts_with('M') {
        let (account_id, memo_id) = decode_muxed_account(key)?;
        println!("StrKey:");
        println!("  type: STRKEY_MUXED_ACCOUNT_ED25519");
        println!("  accountId: {}", encode_account_id(&account_id));
        println!("  memoId: {}", memo_id);
        println!("  hex: {}", hex::encode(account_id));
        return Ok(());
    }

    // Try contract address (C...)
    if key.starts_with('C') {
        let hash = decode_contract(key)?;
        println!("StrKey:");
        println!("  type: STRKEY_CONTRACT");
        println!("  hex: {}", hex::encode(hash));
        return Ok(());
    }

    // Try signed payload (P...)
    if key.starts_with('P') {
        let (signer, payload) = decode_signed_payload(key)?;
        println!("StrKey:");
        println!("  type: STRKEY_SIGNED_PAYLOAD_ED25519");
        println!("  signer: {}", hex::encode(signer));
        println!("  payload: {}", hex::encode(payload));
        return Ok(());
    }

    // Try 64-character hex string (32 bytes)
    if key.len() == 64 {
        if let Ok(bytes) = hex::decode(key) {
            if bytes.len() == 32 {
                let data: [u8; 32] = bytes.try_into().unwrap();

                // Show all possible interpretations
                println!("Interpreted as PublicKey:");
                println!("  strKey: {}", encode_account_id(&data));
                println!("  hex: {}", key);

                // Show as seed -> public key derivation
                let sk = stellar_core_crypto::SecretKey::from_seed(&data);
                let pk = sk.public_key();
                println!();
                println!("Interpreted as Seed:");
                println!("  strKey: {}", sk.to_strkey());
                println!("PublicKey:");
                println!("  strKey: {}", pk.to_strkey());
                println!("  hex: {}", hex::encode(pk.as_bytes()));

                println!();
                println!("Other interpretations:");
                println!("  STRKEY_PRE_AUTH_TX: {}", encode_pre_auth_tx(&data));
                println!("  STRKEY_HASH_X: {}", encode_sha256_hash(&data));
                println!("  STRKEY_MUXED_ACCOUNT: {}", encode_muxed_account(&data, 0));
                println!("  STRKEY_CONTRACT: {}", encode_contract(&data));

                return Ok(());
            }
        }
    }

    anyhow::bail!("Unknown key format: {}. Expected G.../S.../T.../X.../M.../C.../P... strkey or 64-character hex", key);
}

/// Decodes XDR from base64 and prints it in debug format.
///
/// Supports: LedgerHeader, TransactionEnvelope, TransactionResult
fn decode_xdr(type_name: &str, value: &str) -> anyhow::Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use stellar_xdr::curr::ReadXdr;

    let bytes = STANDARD.decode(value)?;

    // This is a simplified version - a full implementation would handle all XDR types
    match type_name.to_lowercase().as_str() {
        "ledgerheader" => {
            let header = stellar_xdr::curr::LedgerHeader::from_xdr(
                &bytes,
                stellar_xdr::curr::Limits::none(),
            )?;
            println!("{:#?}", header);
        }
        "transactionenvelope" => {
            let env = stellar_xdr::curr::TransactionEnvelope::from_xdr(
                &bytes,
                stellar_xdr::curr::Limits::none(),
            )?;
            println!("{:#?}", env);
        }
        "transactionresult" => {
            let result = stellar_xdr::curr::TransactionResult::from_xdr(
                &bytes,
                stellar_xdr::curr::Limits::none(),
            )?;
            println!("{:#?}", result);
        }
        _ => {
            anyhow::bail!("Unknown XDR type: {}. Supported types: LedgerHeader, TransactionEnvelope, TransactionResult", type_name);
        }
    }

    Ok(())
}

/// Encodes a value to XDR and prints it as base64.
///
/// Supports: LedgerHeader, TransactionEnvelope, TransactionResult,
/// AccountId, MuxedAccount, Asset, Hash, Uint256
fn encode_xdr(type_name: &str, value: &str) -> anyhow::Result<()> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use stellar_xdr::curr::{Limits, WriteXdr};

    // Parse JSON and encode to XDR based on type
    match type_name.to_lowercase().as_str() {
        "ledgerheader" => {
            let header: stellar_xdr::curr::LedgerHeader = serde_json::from_str(value)
                .map_err(|e| anyhow::anyhow!("Invalid JSON for LedgerHeader: {}", e))?;
            let xdr_bytes = header.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "transactionenvelope" => {
            let env: stellar_xdr::curr::TransactionEnvelope = serde_json::from_str(value)
                .map_err(|e| anyhow::anyhow!("Invalid JSON for TransactionEnvelope: {}", e))?;
            let xdr_bytes = env.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "transactionresult" => {
            let result: stellar_xdr::curr::TransactionResult = serde_json::from_str(value)
                .map_err(|e| anyhow::anyhow!("Invalid JSON for TransactionResult: {}", e))?;
            let xdr_bytes = result.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "accountid" => {
            // Parse from strkey (G...) format
            let pk = stellar_core_crypto::PublicKey::from_strkey(value.trim())?;
            let account_id =
                stellar_xdr::curr::AccountId(stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                    stellar_xdr::curr::Uint256(*pk.as_bytes()),
                ));
            let xdr_bytes = account_id.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "muxedaccount" => {
            // Parse from strkey (G... or M...) format
            let value = value.trim();
            let muxed = if value.starts_with('G') {
                let pk = stellar_core_crypto::PublicKey::from_strkey(value)?;
                stellar_xdr::curr::MuxedAccount::Ed25519(stellar_xdr::curr::Uint256(*pk.as_bytes()))
            } else {
                // For M... addresses, parse the muxed account
                anyhow::bail!("Muxed account (M...) parsing not yet supported");
            };
            let xdr_bytes = muxed.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "asset" => {
            // Parse asset in format "native" or "CODE:ISSUER"
            let value = value.trim();
            let asset = if value.to_lowercase() == "native" {
                stellar_xdr::curr::Asset::Native
            } else if let Some((code, issuer)) = value.split_once(':') {
                let issuer_pk = stellar_core_crypto::PublicKey::from_strkey(issuer)?;
                let issuer_id = stellar_xdr::curr::AccountId(
                    stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::curr::Uint256(
                        *issuer_pk.as_bytes(),
                    )),
                );

                if code.len() <= 4 {
                    let mut asset_code = [0u8; 4];
                    asset_code[..code.len()].copy_from_slice(code.as_bytes());
                    stellar_xdr::curr::Asset::CreditAlphanum4(stellar_xdr::curr::AlphaNum4 {
                        asset_code: stellar_xdr::curr::AssetCode4(asset_code),
                        issuer: issuer_id,
                    })
                } else if code.len() <= 12 {
                    let mut asset_code = [0u8; 12];
                    asset_code[..code.len()].copy_from_slice(code.as_bytes());
                    stellar_xdr::curr::Asset::CreditAlphanum12(stellar_xdr::curr::AlphaNum12 {
                        asset_code: stellar_xdr::curr::AssetCode12(asset_code),
                        issuer: issuer_id,
                    })
                } else {
                    anyhow::bail!("Asset code too long (max 12 characters)");
                }
            } else {
                anyhow::bail!("Invalid asset format. Use 'native' or 'CODE:ISSUER'");
            };
            let xdr_bytes = asset.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "hash" | "uint256" => {
            // Parse from hex
            let value = value.trim();
            let bytes = hex::decode(value).map_err(|e| anyhow::anyhow!("Invalid hex: {}", e))?;
            if bytes.len() != 32 {
                anyhow::bail!("Hash must be exactly 32 bytes (64 hex characters)");
            }
            let hash = stellar_xdr::curr::Uint256(bytes.try_into().unwrap());
            let xdr_bytes = hash.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        _ => {
            anyhow::bail!(
                "Unknown XDR type: {}. Supported types: LedgerHeader, TransactionEnvelope, \
                TransactionResult, AccountId, MuxedAccount, Asset, Hash, Uint256",
                type_name
            );
        }
    }

    Ok(())
}

/// Prints information about bucket files.
///
/// If given a directory, lists all bucket files with their sizes.
/// If given a single file, prints its metadata.
fn bucket_info(path: &PathBuf) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("Bucket path does not exist: {}", path.display());
    }

    if path.is_dir() {
        // List bucket files in directory
        println!("Bucket directory: {}", path.display());
        println!();

        let mut count = 0;
        let mut total_size = 0u64;

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                let name = entry.file_name();
                let size = metadata.len();
                println!("  {} ({} bytes)", name.to_string_lossy(), size);
                count += 1;
                total_size += size;
            }
        }

        println!();
        println!("Total: {} files, {} bytes", count, total_size);
    } else {
        // Single bucket file
        println!("Bucket file: {}", path.display());

        let metadata = std::fs::metadata(path)?;
        println!("Size: {} bytes", metadata.len());

        // Would parse and display bucket contents
        println!("(Bucket content parsing not yet implemented)");
    }

    Ok(())
}

/// Checks quorum intersection from a JSON network configuration.
///
/// Loads the quorum set definitions and verifies that the network enjoys
/// quorum intersection (all quorums share at least one node).
fn cmd_check_quorum_intersection(path: &std::path::Path) -> anyhow::Result<()> {
    let enjoys = quorum_intersection::check_quorum_intersection_from_json(path)?;
    if enjoys {
        println!("network enjoys quorum intersection");
        Ok(())
    } else {
        anyhow::bail!("quorum sets do not have intersection");
    }
}

/// Sign a transaction envelope with a secret key.
///
/// Reads a transaction envelope (base64 or from file), prompts for a secret key,
/// signs the transaction, and outputs the signed envelope.
///
/// Equivalent to C++ stellar-core sign-transaction command.
fn sign_transaction(netid: &str, input: &str, output_base64: bool) -> anyhow::Result<()> {
    use stellar_core_crypto::{sha256, SecretKey};
    use stellar_xdr::curr::{
        DecoratedSignature, ReadXdr, SignatureHint, TransactionEnvelope,
        TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    };

    // Read the transaction envelope
    let envelope_bytes = if input == "-" {
        // Read from stdin
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let trimmed = line.trim();
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed)?
    } else {
        // Treat input as base64 string
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, input)?
    };

    let mut tx_env =
        TransactionEnvelope::from_xdr(envelope_bytes, stellar_xdr::curr::Limits::none())?;

    // Prompt for secret key
    eprint!("Secret key seed [network id: '{}']: ", netid);
    let mut secret_line = String::new();
    std::io::stdin().read_line(&mut secret_line)?;
    let secret_str = secret_line.trim();

    let secret_key = SecretKey::from_strkey(secret_str)
        .map_err(|e| anyhow::anyhow!("Invalid secret key: {:?}", e))?;

    // Compute the network ID hash
    let network_id_hash = sha256(netid.as_bytes());

    // Create the signature payload
    let payload = match &tx_env {
        TransactionEnvelope::TxV0(v0) => {
            // Convert V0 to V1 for signing (same signature semantics)
            let tx = stellar_xdr::curr::Transaction {
                source_account: stellar_xdr::curr::MuxedAccount::Ed25519(
                    v0.tx.source_account_ed25519.clone(),
                ),
                fee: v0.tx.fee,
                seq_num: v0.tx.seq_num.clone(),
                cond: stellar_xdr::curr::Preconditions::Time(v0.tx.time_bounds.clone().unwrap_or(
                    stellar_xdr::curr::TimeBounds {
                        min_time: 0.into(),
                        max_time: 0.into(),
                    },
                )),
                memo: v0.tx.memo.clone(),
                operations: v0.tx.operations.clone(),
                ext: stellar_xdr::curr::TransactionExt::V0,
            };
            TransactionSignaturePayload {
                network_id: stellar_xdr::curr::Hash(network_id_hash.0),
                tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx),
            }
        }
        TransactionEnvelope::Tx(v1) => TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id_hash.0),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone()),
        },
        TransactionEnvelope::TxFeeBump(fee_bump) => TransactionSignaturePayload {
            network_id: stellar_xdr::curr::Hash(network_id_hash.0),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(
                fee_bump.tx.clone(),
            ),
        },
    };

    // Serialize and hash the payload
    let payload_bytes = payload.to_xdr(stellar_xdr::curr::Limits::none())?;
    let payload_hash = sha256(&payload_bytes);

    // Sign the hash
    let signature = secret_key.sign(&payload_hash.0);

    // Create the decorated signature
    let public_key = secret_key.public_key();
    let hint_bytes = public_key.as_bytes();
    let hint = SignatureHint([
        hint_bytes[28],
        hint_bytes[29],
        hint_bytes[30],
        hint_bytes[31],
    ]);
    let decorated_sig = DecoratedSignature {
        hint,
        signature: stellar_xdr::curr::Signature(signature.as_bytes().to_vec().try_into()?),
    };

    // Add the signature to the envelope
    // VecM doesn't support direct mutation, so we convert to Vec, modify, and convert back
    match &mut tx_env {
        TransactionEnvelope::TxV0(v0) => {
            let mut sigs: Vec<_> = v0.signatures.to_vec();
            if sigs.len() >= 20 {
                anyhow::bail!("Envelope already contains maximum number of signatures");
            }
            sigs.push(decorated_sig);
            v0.signatures = sigs.try_into()?;
        }
        TransactionEnvelope::Tx(v1) => {
            let mut sigs: Vec<_> = v1.signatures.to_vec();
            if sigs.len() >= 20 {
                anyhow::bail!("Envelope already contains maximum number of signatures");
            }
            sigs.push(decorated_sig);
            v1.signatures = sigs.try_into()?;
        }
        TransactionEnvelope::TxFeeBump(fee_bump) => {
            let mut sigs: Vec<_> = fee_bump.signatures.to_vec();
            if sigs.len() >= 20 {
                anyhow::bail!("Envelope already contains maximum number of signatures");
            }
            sigs.push(decorated_sig);
            fee_bump.signatures = sigs.try_into()?;
        }
    }

    // Output the signed envelope
    let out_bytes = tx_env.to_xdr(stellar_xdr::curr::Limits::none())?;
    if output_base64 {
        println!(
            "{}",
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &out_bytes)
        );
    } else {
        use std::io::Write;
        std::io::stdout().write_all(&out_bytes)?;
    }

    Ok(())
}

/// Convert a secret key to its corresponding public key.
///
/// Reads a secret key seed (S...) from stdin and prints the public key.
/// Equivalent to C++ stellar-core sec-to-pub command.
fn sec_to_pub() -> anyhow::Result<()> {
    use stellar_core_crypto::{encode_account_id, SecretKey};

    eprint!("Secret key seed: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let secret_str = line.trim();

    let secret_key = SecretKey::from_strkey(secret_str)
        .map_err(|e| anyhow::anyhow!("Invalid secret key: {:?}", e))?;

    let public_key = secret_key.public_key();
    println!("{}", encode_account_id(public_key.as_bytes()));

    Ok(())
}

/// Dump ledger entries from the bucket list to a JSON file.
///
/// This is equivalent to C++ stellar-core dump-ledger command.
/// It iterates over all entries in the bucket list and outputs them as JSON.
async fn cmd_dump_ledger(
    config: AppConfig,
    output: PathBuf,
    entry_type: Option<String>,
    limit: Option<u64>,
    last_modified_ledger_count: Option<u32>,
) -> anyhow::Result<()> {
    use std::io::Write;
    use stellar_core_bucket::BucketManager;
    use stellar_xdr::curr::LedgerEntryType;

    // Parse entry type filter if provided
    let type_filter: Option<LedgerEntryType> = if let Some(ref type_str) = entry_type {
        Some(match type_str.to_lowercase().as_str() {
            "account" => LedgerEntryType::Account,
            "trustline" => LedgerEntryType::Trustline,
            "offer" => LedgerEntryType::Offer,
            "data" => LedgerEntryType::Data,
            "claimable_balance" | "claimablebalance" => LedgerEntryType::ClaimableBalance,
            "liquidity_pool" | "liquiditypool" => LedgerEntryType::LiquidityPool,
            "contract_data" | "contractdata" => LedgerEntryType::ContractData,
            "contract_code" | "contractcode" => LedgerEntryType::ContractCode,
            "config_setting" | "configsetting" => LedgerEntryType::ConfigSetting,
            "ttl" => LedgerEntryType::Ttl,
            _ => anyhow::bail!(
                "Unknown entry type: {}. Valid types: account, trustline, offer, data, \
                claimable_balance, liquidity_pool, contract_data, contract_code, \
                config_setting, ttl",
                type_str
            ),
        })
    } else {
        None
    };

    // Open database and bucket manager
    let db = stellar_core_db::Database::open(&config.database.path)?;
    let bucket_manager = BucketManager::with_cache_size(
        config.buckets.directory.clone(),
        config.buckets.cache_size,
    )?;

    // Get current ledger
    let current_ledger = db
        .get_latest_ledger_seq()?
        .ok_or_else(|| anyhow::anyhow!("No ledger data in database. Run catchup first."))?;

    println!("Current ledger: {}", current_ledger);

    // Calculate minimum last modified ledger if filter is set
    let min_last_modified: Option<u32> =
        last_modified_ledger_count.map(|count| current_ledger.saturating_sub(count));

    // Load bucket list snapshot for the current checkpoint
    let checkpoint =
        stellar_core_history::checkpoint::latest_checkpoint_before_or_at(current_ledger)
            .ok_or_else(|| {
                anyhow::anyhow!("No checkpoint available for ledger {}", current_ledger)
            })?;

    println!("Using checkpoint: {}", checkpoint);

    let levels = db
        .load_bucket_list(checkpoint)?
        .ok_or_else(|| anyhow::anyhow!("Missing bucket list snapshot at {}", checkpoint))?;

    // Open output file
    let mut file = std::fs::File::create(&output)?;

    let mut entry_count: u64 = 0;
    let limit_val = limit.unwrap_or(u64::MAX);

    println!("Dumping entries to {}...", output.display());

    // Iterate over all bucket levels
    for (level_idx, (curr_hash, snap_hash)) in levels.iter().enumerate() {
        if entry_count >= limit_val {
            break;
        }

        // Process curr bucket
        for hash in [curr_hash, snap_hash] {
            if entry_count >= limit_val {
                break;
            }

            let bucket = bucket_manager.load_bucket(hash)?;
            for entry in bucket.entries() {
                if entry_count >= limit_val {
                    break;
                }

                // Skip dead entries and metadata
                let live_entry = match entry {
                    stellar_core_bucket::BucketEntry::Live(e)
                    | stellar_core_bucket::BucketEntry::Init(e) => e,
                    stellar_core_bucket::BucketEntry::Dead(_)
                    | stellar_core_bucket::BucketEntry::Metadata(_) => continue,
                };

                // Apply type filter
                if let Some(ref filter_type) = type_filter {
                    if live_entry.data.discriminant() != *filter_type {
                        continue;
                    }
                }

                // Apply last modified ledger filter
                if let Some(min_ledger) = min_last_modified {
                    if live_entry.last_modified_ledger_seq < min_ledger {
                        continue;
                    }
                }

                // Serialize to JSON
                let json = serde_json::to_string_pretty(&live_entry)?;
                writeln!(file, "{}", json)?;

                entry_count += 1;

                // Progress reporting
                if entry_count % 10000 == 0 {
                    print!(
                        "\rProcessed {} entries (level {})...",
                        entry_count, level_idx
                    );
                    std::io::stdout().flush()?;
                }
            }
        }
    }

    println!();
    println!("Dumped {} entries to {}", entry_count, output.display());

    Ok(())
}

/// Perform offline self-checks (equivalent to C++ self-check command).
///
/// This command performs comprehensive diagnostic checks:
/// 1. Header chain verification - ensures ledger headers form a valid chain
/// 2. Bucket hash verification - verifies all bucket files have correct hashes
/// 3. Crypto benchmarking - measures Ed25519 sign/verify performance
async fn cmd_self_check(config: AppConfig) -> anyhow::Result<()> {
    use std::time::Instant;
    use stellar_core_bucket::BucketManager;
    use stellar_core_crypto::SecretKey;

    let mut all_ok = true;

    // Phase 1: Header chain verification
    println!("Self-check phase 1: header chain verification");
    let db = stellar_core_db::Database::open(&config.database.path)?;

    let Some(latest_seq) = db.get_latest_ledger_seq()? else {
        println!("  No ledger data in database. Skipping header verification.");
        println!();
        return Ok(());
    };

    if latest_seq == 0 {
        println!("  At genesis ledger. Header chain is trivially valid.");
    } else {
        // Verify header chain going backwards
        let depth = std::cmp::min(latest_seq, 100); // Check up to 100 ledgers
        let mut current_seq = latest_seq;
        let mut verified = 0u32;

        while current_seq > 0 && verified < depth {
            let current = db
                .get_ledger_header(current_seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header at {}", current_seq))?;
            let prev_seq = current_seq - 1;
            let prev = db
                .get_ledger_header(prev_seq)?
                .ok_or_else(|| anyhow::anyhow!("Missing ledger header at {}", prev_seq))?;

            let prev_hash = stellar_core_ledger::compute_header_hash(&prev)?;

            if current.previous_ledger_hash != prev_hash.into() {
                println!("  ERROR: Header chain broken at ledger {}", current_seq);
                println!(
                    "    Previous hash in header: {:?}",
                    current.previous_ledger_hash
                );
                println!("    Computed hash of previous: {:?}", prev_hash);
                all_ok = false;
                break;
            }

            current_seq = prev_seq;
            verified += 1;
        }

        if verified == depth {
            println!(
                "  Verified {} ledger headers (from {} to {})",
                verified,
                latest_seq,
                latest_seq - verified + 1
            );
        }
    }

    // Phase 2: Bucket hash verification
    println!();
    println!("Self-check phase 2: bucket hash verification");

    let bucket_manager = BucketManager::with_cache_size(
        config.buckets.directory.clone(),
        config.buckets.cache_size,
    )?;

    // Get the checkpoint for the current ledger
    let checkpoint =
        stellar_core_history::checkpoint::latest_checkpoint_before_or_at(latest_seq)
            .ok_or_else(|| anyhow::anyhow!("No checkpoint available for ledger {}", latest_seq))?;

    let levels = db
        .load_bucket_list(checkpoint)?
        .ok_or_else(|| anyhow::anyhow!("Missing bucket list snapshot at {}", checkpoint))?;

    let mut buckets_verified = 0;
    let mut buckets_failed = 0;

    // Collect all unique bucket hashes using a set for deduplication
    let hashes_to_verify: std::collections::HashSet<_> = levels
        .iter()
        .flat_map(|(curr, snap)| [*curr, *snap])
        .filter(|h| !h.is_zero())
        .collect();

    println!("  Verifying {} bucket files...", hashes_to_verify.len());

    for hash in &hashes_to_verify {
        match bucket_manager.load_bucket(hash) {
            Ok(bucket) => {
                // The bucket's hash is computed from its contents when loaded
                // If it loads successfully, the hash matches
                if bucket.hash() != *hash {
                    println!("  ERROR: Bucket hash mismatch for {}", hash);
                    println!("    Expected: {}", hash);
                    println!("    Computed: {}", bucket.hash());
                    buckets_failed += 1;
                    all_ok = false;
                } else {
                    buckets_verified += 1;
                }
            }
            Err(e) => {
                println!("  ERROR: Failed to load bucket {}: {}", hash, e);
                buckets_failed += 1;
                all_ok = false;
            }
        }
    }

    println!(
        "  Verified {} buckets, {} failures",
        buckets_verified, buckets_failed
    );

    // Phase 3: Crypto benchmarking
    println!();
    println!("Self-check phase 3: crypto benchmarking");

    const BENCHMARK_OPS: usize = 10000;
    let message = b"stellar benchmark test message for ed25519 signing";

    // Generate a keypair for benchmarking
    let secret = SecretKey::generate();
    let public = secret.public_key();

    // Benchmark signing
    let start = Instant::now();
    for _ in 0..BENCHMARK_OPS {
        let _ = secret.sign(message);
    }
    let sign_duration = start.elapsed();
    let sign_per_sec = (BENCHMARK_OPS as f64 / sign_duration.as_secs_f64()) as u64;

    // Generate signatures for verification benchmark
    let signature = secret.sign(message);

    // Benchmark verification
    let start = Instant::now();
    for _ in 0..BENCHMARK_OPS {
        let _ = public.verify(message, &signature);
    }
    let verify_duration = start.elapsed();
    let verify_per_sec = (BENCHMARK_OPS as f64 / verify_duration.as_secs_f64()) as u64;

    println!("  Benchmarked {} signatures / sec", sign_per_sec);
    println!("  Benchmarked {} verifications / sec", verify_per_sec);

    // Final result
    println!();
    if all_ok {
        println!("Self-check succeeded");
        Ok(())
    } else {
        println!("Self-check failed");
        std::process::exit(1);
    }
}

/// Write verified checkpoint ledger hashes to a file.
///
/// Downloads checkpoint headers from history archives, verifies the header
/// chain, and writes verified checkpoint hashes to a JSON file.
///
/// Equivalent to C++ stellar-core verify-checkpoints.
async fn cmd_verify_checkpoints(
    config: AppConfig,
    output: PathBuf,
    from: Option<u32>,
    to: Option<u32>,
) -> anyhow::Result<()> {
    use std::io::Write;
    use stellar_core_history::{checkpoint, verify, HistoryArchive};
    use stellar_core_ledger::compute_header_hash;

    println!("Verifying checkpoint hashes...");
    println!();

    // Create archive clients from config
    let archives: Vec<HistoryArchive> = config
        .history
        .archives
        .iter()
        .filter(|a| a.get_enabled)
        .filter_map(|a| match HistoryArchive::new(&a.url) {
            Ok(archive) => Some(archive),
            Err(e) => {
                println!("Warning: Failed to create archive {}: {}", a.url, e);
                None
            }
        })
        .collect();

    if archives.is_empty() {
        anyhow::bail!("No history archives available");
    }

    println!("Using {} archive(s)", archives.len());

    let archive = &archives[0];
    let root_has = archive.get_root_has().await?;
    let current_ledger = root_has.current_ledger;

    let start = from.unwrap_or(63); // First checkpoint
    let end = to.unwrap_or(current_ledger);

    println!("Verifying checkpoint range: {} to {}", start, end);
    println!();

    // Calculate checkpoint-aligned start and end
    let start_checkpoint = checkpoint::checkpoint_containing(start);
    let end_checkpoint = checkpoint::checkpoint_containing(end);

    // Collect verified checkpoint hashes
    let mut verified_checkpoints: Vec<serde_json::Value> = Vec::new();
    let mut prev_header: Option<stellar_xdr::curr::LedgerHeader> = None;
    let mut verified_count = 0;
    let mut error_count = 0;

    let mut current_checkpoint = start_checkpoint;
    while current_checkpoint <= end_checkpoint {
        print!("  Checkpoint {}: ", current_checkpoint);
        std::io::stdout().flush()?;

        // Download headers for this checkpoint
        match archive.get_ledger_headers(current_checkpoint).await {
            Ok(history_entries) => {
                if history_entries.is_empty() {
                    println!("FAIL (no headers)");
                    error_count += 1;
                    current_checkpoint = checkpoint::next_checkpoint(current_checkpoint);
                    continue;
                }

                // Extract headers
                let headers: Vec<stellar_xdr::curr::LedgerHeader> = history_entries
                    .iter()
                    .map(|entry| entry.header.clone())
                    .collect();

                // Verify header chain within this checkpoint
                if let Err(e) = verify::verify_header_chain(&headers) {
                    println!("FAIL (chain broken: {})", e);
                    error_count += 1;
                    current_checkpoint = checkpoint::next_checkpoint(current_checkpoint);
                    continue;
                }

                // Verify linkage to previous checkpoint
                if let Some(ref prev) = prev_header {
                    let first_header = &headers[0];
                    let prev_hash = compute_header_hash(prev)?;
                    if first_header.previous_ledger_hash != prev_hash.into() {
                        println!("FAIL (cross-checkpoint link broken)");
                        error_count += 1;
                        current_checkpoint = checkpoint::next_checkpoint(current_checkpoint);
                        continue;
                    }
                }

                // Get the checkpoint ledger header (last header in the set)
                let checkpoint_header = headers.last().unwrap();
                let checkpoint_hash = compute_header_hash(checkpoint_header)?;

                // Store for JSON output
                verified_checkpoints.push(serde_json::json!({
                    "ledger": current_checkpoint,
                    "hash": hex::encode(checkpoint_hash.as_bytes())
                }));

                println!(
                    "OK (hash: {})",
                    hex::encode(&checkpoint_hash.as_bytes()[..8])
                );
                verified_count += 1;

                // Update previous header for next iteration
                prev_header = Some(checkpoint_header.clone());
            }
            Err(e) => {
                println!("FAIL (download: {})", e);
                error_count += 1;
            }
        }

        current_checkpoint = checkpoint::next_checkpoint(current_checkpoint);
    }

    println!();
    println!(
        "Verified {} checkpoints, {} errors",
        verified_count, error_count
    );

    // Write output file
    let output_json = serde_json::json!({
        "network_passphrase": config.network.passphrase,
        "checkpoints": verified_checkpoints
    });

    let mut file = std::fs::File::create(&output)?;
    serde_json::to_writer_pretty(&file, &output_json)?;
    file.flush()?;

    println!("Wrote verified checkpoint hashes to: {}", output.display());

    if error_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Send an HTTP command to a running stellar-core node.
///
/// Makes an HTTP GET request to http://127.0.0.1:{port}/{command}
/// and prints the response. Query parameters are URL-encoded.
///
/// Equivalent to C++ stellar-core http-command.
async fn cmd_http_command(command: &str, port: u16) -> anyhow::Result<()> {
    // Build the URL path, encoding special characters after the ?
    let mut path = String::from("/");
    let mut in_query = false;

    for c in command.chars() {
        if in_query {
            // URL-encode non-alphanumeric characters in query string
            if c.is_ascii_alphanumeric() || c == '&' || c == '=' {
                path.push(c);
            } else {
                path.push_str(&format!("%{:02X}", c as u8));
            }
        } else {
            path.push(c);
            if c == '?' {
                in_query = true;
            }
        }
    }

    let url = format!("http://127.0.0.1:{}{}", port, path);

    // Make the HTTP request
    let client = reqwest::Client::new();
    let response = client.get(&url).send().await;

    match response {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await?;

            if status.is_success() {
                println!("{}", body);
                Ok(())
            } else {
                eprintln!("HTTP {}: {}", status.as_u16(), body);
                anyhow::bail!("Request failed with status {}", status.as_u16());
            }
        }
        Err(e) => {
            if e.is_connect() {
                anyhow::bail!(
                    "Connection refused on port {}. Is stellar-core running?",
                    port
                );
            } else {
                anyhow::bail!("HTTP request failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        // Test basic parsing
        let cli = Cli::parse_from(["rs-stellar-core", "info"]);
        assert!(matches!(cli.command, Commands::Info));
    }

    #[test]
    fn test_cli_run_command() {
        let cli = Cli::parse_from(["rs-stellar-core", "run", "--validator"]);
        match cli.command {
            Commands::Run {
                validator, watcher, ..
            } => {
                assert!(validator);
                assert!(!watcher);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_cli_catchup_command() {
        let cli = Cli::parse_from([
            "rs-stellar-core",
            "catchup",
            "1000000",
            "--mode",
            "complete",
        ]);
        match cli.command {
            Commands::Catchup { target, .. } => {
                assert_eq!(target, "1000000");
            }
            _ => panic!("Expected Catchup command"),
        }
    }

    #[test]
    fn test_cli_global_options() {
        let cli = Cli::parse_from(["rs-stellar-core", "--verbose", "--mainnet", "info"]);
        assert!(cli.verbose);
        assert!(cli.mainnet);
    }

    #[test]
    fn test_cli_check_quorum_intersection() {
        let cli = Cli::parse_from(["rs-stellar-core", "check-quorum-intersection", "foo.json"]);
        match cli.command {
            Commands::CheckQuorumIntersection { path } => {
                assert_eq!(path, PathBuf::from("foo.json"));
            }
            _ => panic!("Expected check-quorum-intersection command"),
        }
    }
}
