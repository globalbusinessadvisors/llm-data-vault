//! Database Migration CLI Tool
//!
//! Enterprise-grade command-line interface for managing database migrations.
//!
//! # Usage
//!
//! ```bash
//! # Run all pending migrations
//! vault-migrate run
//!
//! # Show migration status
//! vault-migrate status
//!
//! # Revert the last migration
//! vault-migrate revert
//!
//! # Revert all migrations
//! vault-migrate revert-all --confirm
//!
//! # Validate migration checksums
//! vault-migrate validate
//!
//! # Create a new migration file
//! vault-migrate create "add_new_table"
//! ```

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;
use tracing::{error, info, warn, Level};
use tracing_subscriber::fmt::format::FmtSpan;

use vault_migrations::{Migrator, MigrationStatus};

/// Database Migration CLI for LLM Data Vault
#[derive(Parser)]
#[command(name = "vault-migrate")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Database connection URL (can also use DATABASE_URL env var)
    #[arg(short, long, env = "DATABASE_URL")]
    database_url: String,

    /// Maximum number of database connections
    #[arg(long, default_value = "5")]
    max_connections: u32,

    /// Connection timeout in seconds
    #[arg(long, default_value = "30")]
    connect_timeout: u64,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Output format
    #[arg(long, default_value = "text")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Default, clap::ValueEnum)]
enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all pending migrations
    Run {
        /// Dry run - show what would be executed without applying
        #[arg(long)]
        dry_run: bool,
    },

    /// Show migration status
    Status,

    /// Revert the last applied migration
    Revert {
        /// Number of migrations to revert
        #[arg(short, long, default_value = "1")]
        count: usize,

        /// Skip confirmation prompt
        #[arg(long)]
        confirm: bool,
    },

    /// Revert all migrations (dangerous!)
    RevertAll {
        /// Required confirmation flag
        #[arg(long)]
        confirm: bool,
    },

    /// Validate migration checksums
    Validate,

    /// Create a new migration file
    Create {
        /// Migration name (will be prefixed with timestamp)
        name: String,

        /// Create with down migration
        #[arg(long)]
        reversible: bool,
    },

    /// Show information about a specific migration
    Info {
        /// Migration version (timestamp prefix)
        version: i64,
    },

    /// Check if database is up to date
    Check,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Load .env file if present
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_span_events(FmtSpan::CLOSE)
        .with_target(false)
        .init();

    // Create database pool
    let pool = match PgPoolOptions::new()
        .max_connections(cli.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(cli.connect_timeout))
        .connect(&cli.database_url)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to connect to database: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let migrator = Migrator::new(pool);

    let result = match cli.command {
        Commands::Run { dry_run } => run_migrations(&migrator, dry_run, cli.format).await,
        Commands::Status => show_status(&migrator, cli.format).await,
        Commands::Revert { count, confirm } => revert_migrations(&migrator, count, confirm).await,
        Commands::RevertAll { confirm } => revert_all_migrations(&migrator, confirm).await,
        Commands::Validate => validate_migrations(&migrator, cli.format).await,
        Commands::Create { name, reversible } => create_migration(&name, reversible).await,
        Commands::Info { version } => show_migration_info(&migrator, version, cli.format).await,
        Commands::Check => check_migrations(&migrator, cli.format).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run_migrations(migrator: &Migrator, dry_run: bool, format: OutputFormat) -> anyhow::Result<()> {
    let pending = migrator.pending_count().await?;

    if pending == 0 {
        match format {
            OutputFormat::Text => info!("Database is up to date. No migrations to apply."),
            OutputFormat::Json => println!(r#"{{"status": "up_to_date", "applied": 0}}"#),
        }
        return Ok(());
    }

    if dry_run {
        let migrations = migrator.list().await?;
        match format {
            OutputFormat::Text => {
                info!("Dry run - {} migration(s) would be applied:", pending);
                for m in migrations.iter().filter(|m| m.status == MigrationStatus::Pending) {
                    info!("  {} - {}", m.version, m.description);
                }
            }
            OutputFormat::Json => {
                let pending_list: Vec<_> = migrations
                    .iter()
                    .filter(|m| m.status == MigrationStatus::Pending)
                    .map(|m| serde_json::json!({
                        "version": m.version,
                        "description": m.description
                    }))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "dry_run",
                    "pending_count": pending,
                    "migrations": pending_list
                }))?);
            }
        }
        return Ok(());
    }

    match format {
        OutputFormat::Text => info!("Applying {} migration(s)...", pending),
        OutputFormat::Json => {}
    }

    migrator.run().await?;

    match format {
        OutputFormat::Text => info!("Successfully applied {} migration(s)", pending),
        OutputFormat::Json => println!(r#"{{"status": "success", "applied": {}}}"#, pending),
    }

    Ok(())
}

async fn show_status(migrator: &Migrator, format: OutputFormat) -> anyhow::Result<()> {
    let migrations = migrator.list().await?;
    let current_version = migrator.current_version().await?;
    let pending = migrator.pending_count().await?;

    match format {
        OutputFormat::Text => {
            println!("\n=== Migration Status ===\n");
            println!("Current version: {}", current_version.map_or("None".to_string(), |v| v.to_string()));
            println!("Total migrations: {}", migrations.len());
            println!("Pending migrations: {}\n", pending);

            println!("{:<20} {:<50} {:<12} {:<20}", "VERSION", "DESCRIPTION", "STATUS", "APPLIED AT");
            println!("{}", "-".repeat(102));

            for m in &migrations {
                let status = match m.status {
                    MigrationStatus::Applied => "Applied",
                    MigrationStatus::Pending => "Pending",
                    MigrationStatus::Modified => "Modified",
                };
                let applied_at = m.applied_at
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "-".to_string());

                println!("{:<20} {:<50} {:<12} {:<20}",
                    m.version,
                    truncate(&m.description, 48),
                    status,
                    applied_at
                );
            }
            println!();
        }
        OutputFormat::Json => {
            let json = serde_json::json!({
                "current_version": current_version,
                "total_migrations": migrations.len(),
                "pending_migrations": pending,
                "migrations": migrations.iter().map(|m| serde_json::json!({
                    "version": m.version,
                    "description": m.description,
                    "status": format!("{:?}", m.status),
                    "applied_at": m.applied_at
                })).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
    }

    Ok(())
}

async fn revert_migrations(migrator: &Migrator, count: usize, confirm: bool) -> anyhow::Result<()> {
    if !confirm {
        warn!("This will revert {} migration(s). Use --confirm to proceed.", count);
        return Ok(());
    }

    info!("Reverting {} migration(s)...", count);

    for i in 0..count {
        match migrator.revert().await {
            Ok(()) => info!("Reverted migration {} of {}", i + 1, count),
            Err(e) => {
                error!("Failed to revert migration {} of {}: {}", i + 1, count, e);
                return Err(e.into());
            }
        }
    }

    info!("Successfully reverted {} migration(s)", count);
    Ok(())
}

async fn revert_all_migrations(migrator: &Migrator, confirm: bool) -> anyhow::Result<()> {
    if !confirm {
        warn!("WARNING: This will revert ALL migrations and destroy all data!");
        warn!("Use --confirm to proceed.");
        return Ok(());
    }

    warn!("Reverting ALL migrations...");
    migrator.revert_all().await?;
    info!("Successfully reverted all migrations");
    Ok(())
}

async fn validate_migrations(migrator: &Migrator, format: OutputFormat) -> anyhow::Result<()> {
    match migrator.validate().await {
        Ok(()) => {
            match format {
                OutputFormat::Text => info!("All migration checksums are valid"),
                OutputFormat::Json => println!(r#"{{"status": "valid"}}"#),
            }
            Ok(())
        }
        Err(e) => {
            match format {
                OutputFormat::Text => error!("Migration validation failed: {}", e),
                OutputFormat::Json => println!(r#"{{"status": "invalid", "error": "{}"}}"#, e),
            }
            Err(e.into())
        }
    }
}

async fn create_migration(name: &str, reversible: bool) -> anyhow::Result<()> {
    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let safe_name = name
        .to_lowercase()
        .replace(' ', "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();

    let migrations_dir = std::path::Path::new("crates/vault-migrations/migrations");

    if !migrations_dir.exists() {
        std::fs::create_dir_all(migrations_dir)?;
    }

    let up_filename = format!("{}_{}.sql", timestamp, safe_name);
    let up_path = migrations_dir.join(&up_filename);

    let up_content = format!(
        "-- Migration: {}\n\
         -- Created: {}\n\
         \n\
         -- Write your migration SQL here\n\
         \n",
        safe_name,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    std::fs::write(&up_path, up_content)?;
    info!("Created migration: {}", up_path.display());

    if reversible {
        let down_filename = format!("{}_{}.down.sql", timestamp, safe_name);
        let down_path = migrations_dir.join(&down_filename);

        let down_content = format!(
            "-- Rollback migration: {}\n\
             -- Created: {}\n\
             \n\
             -- Write your rollback SQL here\n\
             \n",
            safe_name,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        );

        std::fs::write(&down_path, down_content)?;
        info!("Created rollback: {}", down_path.display());
    }

    Ok(())
}

async fn show_migration_info(migrator: &Migrator, version: i64, format: OutputFormat) -> anyhow::Result<()> {
    let migrations = migrator.list().await?;

    if let Some(m) = migrations.iter().find(|m| m.version == version) {
        match format {
            OutputFormat::Text => {
                println!("\n=== Migration {} ===\n", m.version);
                println!("Description: {}", m.description);
                println!("Status: {:?}", m.status);
                if let Some(applied_at) = m.applied_at {
                    println!("Applied at: {}", applied_at.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                if let Some(checksum) = &m.checksum {
                    println!("Checksum: {}", hex_encode(checksum));
                }
                println!();
            }
            OutputFormat::Json => {
                let json = serde_json::json!({
                    "version": m.version,
                    "description": m.description,
                    "status": format!("{:?}", m.status),
                    "applied_at": m.applied_at,
                    "checksum": m.checksum.as_ref().map(hex_encode)
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
        }
        Ok(())
    } else {
        Err(anyhow::anyhow!("Migration {} not found", version))
    }
}

async fn check_migrations(migrator: &Migrator, format: OutputFormat) -> anyhow::Result<()> {
    let is_up_to_date = migrator.is_up_to_date().await?;
    let pending = migrator.pending_count().await?;

    match format {
        OutputFormat::Text => {
            if is_up_to_date {
                info!("Database is up to date");
            } else {
                warn!("Database has {} pending migration(s)", pending);
            }
        }
        OutputFormat::Json => {
            println!(r#"{{"up_to_date": {}, "pending": {}}}"#, is_up_to_date, pending);
        }
    }

    if is_up_to_date {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Database has pending migrations"))
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn hex_encode(bytes: &Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
