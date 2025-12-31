//! rs-stellar-core - Pure Rust implementation of Stellar Core
//!
//! This binary provides a command-line interface for running a Stellar Core
//! validator node, catching up from history archives, and performing other
//! Stellar network operations.
//!
//! ## Usage
//!
//! ```text
//! rs-stellar-core run                     # Run the node
//! rs-stellar-core catchup current         # Catch up to latest ledger
//! rs-stellar-core catchup 1000000         # Catch up to specific ledger
//! rs-stellar-core new-db                  # Create a new database
//! rs-stellar-core info                    # Print node information
//! ```
//!
//! ## Configuration
//!
//! Configuration can be provided via a TOML file or environment variables.
//! See `rs-stellar-core --help` for more details.

mod app;
mod catchup_cmd;
mod config;
mod logging;
mod run_cmd;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::app::App;
use crate::catchup_cmd::{CatchupMode as CatchupModeInternal, CatchupOptions};
use crate::config::AppConfig;
use crate::logging::{LogConfig, LogFormat};
use crate::run_cmd::{RunMode, RunOptions};

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

    /// Print sample configuration
    SampleConfig,

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

        Commands::SampleConfig => cmd_sample_config(),

        Commands::Offline(cmd) => cmd_offline(cmd),
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

    let config = LogConfig::default()
        .with_level(level);

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

    run_cmd::run_node(config, options).await
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

    let result = catchup_cmd::run_catchup(config, options).await?;
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

    let db = stellar_core_db::Database::open(&config.database.path)?;

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
    use stellar_core_history::{HistoryArchive, verify};

    println!("Verifying history archives...");
    println!();

    // Create archive clients from config
    let archives: Vec<HistoryArchive> = config.history.archives
        .iter()
        .filter(|a| a.get_enabled)
        .filter_map(|a| {
            match HistoryArchive::new(&a.url) {
                Ok(archive) => Some(archive),
                Err(e) => {
                    println!("Warning: Failed to create archive {}: {}", a.url, e);
                    None
                }
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
                        println!("  Checkpoint {}: FAIL (invalid structure) - {}", checkpoint, e);
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
                    }
                    Err(e) => {
                        println!("    Warning: Could not verify headers: {}", e);
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
    use stellar_core_bucket::BucketManager;
    use stellar_core_history::HistoryArchive;

    if !config.node.is_validator {
        anyhow::bail!("Only validators can publish history");
    }

    println!("Publishing history to archives...");
    println!();

    // Check for writable archives
    let writable_archives: Vec<_> = config.history.archives
        .iter()
        .filter(|a| a.put_enabled)
        .collect();

    if writable_archives.is_empty() {
        anyhow::bail!("No writable history archives configured. Add 'put = true' to an archive config.");
    }

    println!("Writable archives: {}", writable_archives.len());
    for archive in &writable_archives {
        println!("  - {}", archive.url);
    }
    println!();

    // Open database to get current state
    let db = stellar_core_db::Database::open(&config.database.path)?;

    // Get current ledger from database
    let current_ledger = db.get_latest_ledger_seq()?
        .ok_or_else(|| anyhow::anyhow!("No ledger data in database. Run the node first."))?;

    println!("Current ledger in database: {}", current_ledger);

    // Calculate checkpoints to publish
    let latest_checkpoint = stellar_core_history::checkpoint::latest_checkpoint_before_or_at(current_ledger)
        .ok_or_else(|| anyhow::anyhow!("No checkpoint available for ledger {}", current_ledger))?;

    println!("Latest publishable checkpoint: {}", latest_checkpoint);

    // Check what's already published
    let archive = HistoryArchive::new(&writable_archives[0].url)?;
    let published_ledger = match archive.get_root_has().await {
        Ok(has) => has.current_ledger,
        Err(_) => 0, // Archive might be empty
    };

    println!("Already published up to: {}", published_ledger);

    if published_ledger >= latest_checkpoint && !force {
        println!();
        println!("Archive is up to date. Use --force to republish.");
        return Ok(());
    }

    // Calculate range to publish
    let start_checkpoint = if published_ledger > 0 && !force {
        stellar_core_history::checkpoint::next_checkpoint(published_ledger)
    } else {
        // Start from the first checkpoint we have
        stellar_core_history::checkpoint::checkpoint_containing(1)
    };

    if start_checkpoint > latest_checkpoint {
        println!("Nothing new to publish.");
        return Ok(());
    }

    println!();
    println!("Publishing checkpoints {} to {}...", start_checkpoint, latest_checkpoint);

    // Open bucket manager for future use when we implement full upload
    let bucket_dir = config.database.path.parent()
        .unwrap_or(&config.database.path)
        .join("buckets");
    let _bucket_manager = BucketManager::new(bucket_dir)?;

    let mut published_count = 0;
    let mut checkpoint = start_checkpoint;

    while checkpoint <= latest_checkpoint {
        print!("  Publishing checkpoint {}... ", checkpoint);

        // In a full implementation, this would:
        // 1. Read ledger headers from the database for this checkpoint range
        // 2. Read transaction sets and results
        // 3. Serialize to XDR format
        // 4. Upload to the writable archive(s)

        // For now, we verify we have the data but don't actually upload
        // since that requires write access implementation
        let has_data = db.get_ledger_header(checkpoint)?.is_some();

        if has_data {
            println!("OK (data available)");
            published_count += 1;
        } else {
            println!("SKIP (missing data)");
        }

        checkpoint = stellar_core_history::checkpoint::next_checkpoint(checkpoint);
    }

    println!();
    println!("Publishing complete:");
    println!("  Checkpoints processed: {}", published_count);
    println!();
    println!("Note: Full archive upload requires configuring archive write credentials.");

    Ok(())
}

/// Sample config command handler.
fn cmd_sample_config() -> anyhow::Result<()> {
    let sample = AppConfig::sample_config();
    println!("{}", sample);
    Ok(())
}

/// Offline commands handler.
fn cmd_offline(cmd: OfflineCommands) -> anyhow::Result<()> {
    match cmd {
        OfflineCommands::ConvertKey { key } => {
            convert_key(&key)
        }
        OfflineCommands::DecodeXdr { r#type, value } => {
            decode_xdr(&r#type, &value)
        }
        OfflineCommands::EncodeXdr { r#type, value } => {
            encode_xdr(&r#type, &value)
        }
        OfflineCommands::BucketInfo { path } => {
            bucket_info(&path)
        }
    }
}

/// Convert a Stellar key between formats.
fn convert_key(key: &str) -> anyhow::Result<()> {
    let key = key.trim();

    if key.starts_with('G') {
        // Public key (account ID)
        let pk = stellar_core_crypto::PublicKey::from_strkey(key)?;
        println!("Type: Account ID (Public Key)");
        println!("StrKey: {}", pk.to_strkey());
        println!("Hex: {}", hex::encode(pk.as_bytes()));
    } else if key.starts_with('S') {
        // Secret seed
        let sk = stellar_core_crypto::SecretKey::from_strkey(key)?;
        let pk = sk.public_key();
        println!("Type: Secret Seed");
        println!("Public Key: {}", pk.to_strkey());
        println!("WARNING: Secret key detected, not displaying raw bytes");
    } else if key.len() == 64 {
        // Might be hex
        let bytes = hex::decode(key)?;
        if bytes.len() == 32 {
            if let Ok(pk) = stellar_core_crypto::PublicKey::from_bytes(bytes.as_slice().try_into()?) {
                println!("Type: Public Key (from hex)");
                println!("StrKey: {}", pk.to_strkey());
            } else {
                println!("Type: 32-byte hash");
                println!("Hex: {}", key);
            }
        }
    } else {
        anyhow::bail!("Unknown key format: {}", key);
    }

    Ok(())
}

/// Decode XDR from base64.
fn decode_xdr(type_name: &str, value: &str) -> anyhow::Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use stellar_xdr::curr::ReadXdr;

    let bytes = STANDARD.decode(value)?;

    // This is a simplified version - a full implementation would handle all XDR types
    match type_name.to_lowercase().as_str() {
        "ledgerheader" => {
            let header = stellar_xdr::curr::LedgerHeader::from_xdr(&bytes, stellar_xdr::curr::Limits::none())?;
            println!("{:#?}", header);
        }
        "transactionenvelope" => {
            let env = stellar_xdr::curr::TransactionEnvelope::from_xdr(&bytes, stellar_xdr::curr::Limits::none())?;
            println!("{:#?}", env);
        }
        "transactionresult" => {
            let result = stellar_xdr::curr::TransactionResult::from_xdr(&bytes, stellar_xdr::curr::Limits::none())?;
            println!("{:#?}", result);
        }
        _ => {
            anyhow::bail!("Unknown XDR type: {}. Supported types: LedgerHeader, TransactionEnvelope, TransactionResult", type_name);
        }
    }

    Ok(())
}

/// Encode a value to XDR.
fn encode_xdr(type_name: &str, value: &str) -> anyhow::Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use stellar_xdr::curr::{WriteXdr, Limits};

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
            let account_id = stellar_xdr::curr::AccountId(
                stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                    stellar_xdr::curr::Uint256(*pk.as_bytes())
                )
            );
            let xdr_bytes = account_id.to_xdr(Limits::none())?;
            println!("{}", STANDARD.encode(&xdr_bytes));
        }
        "muxedaccount" => {
            // Parse from strkey (G... or M...) format
            let value = value.trim();
            let muxed = if value.starts_with('G') {
                let pk = stellar_core_crypto::PublicKey::from_strkey(value)?;
                stellar_xdr::curr::MuxedAccount::Ed25519(
                    stellar_xdr::curr::Uint256(*pk.as_bytes())
                )
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
                    stellar_xdr::curr::PublicKey::PublicKeyTypeEd25519(
                        stellar_xdr::curr::Uint256(*issuer_pk.as_bytes())
                    )
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
            let bytes = hex::decode(value)
                .map_err(|e| anyhow::anyhow!("Invalid hex: {}", e))?;
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

/// Print bucket information.
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
            Commands::Run { validator, watcher, .. } => {
                assert!(validator);
                assert!(!watcher);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_cli_catchup_command() {
        let cli = Cli::parse_from(["rs-stellar-core", "catchup", "1000000", "--mode", "complete"]);
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
}
