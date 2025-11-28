//! Database migrations for LLM Data Vault.
//!
//! This crate provides database schema management using SQLx migrations.
//! It supports PostgreSQL and includes all schema definitions for the
//! LLM Data Vault system.
//!
//! # Usage
//!
//! ```rust,no_run
//! use vault_migrations::Migrator;
//! use sqlx::PgPool;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let pool = PgPool::connect("postgres://localhost/vault").await?;
//!
//!     // Run all pending migrations
//!     Migrator::new(pool).run().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # CLI Tool
//!
//! The crate includes a CLI tool for managing migrations:
//!
//! ```bash
//! # Run all pending migrations
//! vault-migrate run
//!
//! # Show migration status
//! vault-migrate status
//!
//! # Revert the last migration
//! vault-migrate revert --confirm
//!
//! # Validate migration checksums
//! vault-migrate validate
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod migrator;

pub use error::{MigrationError, Result};
pub use migrator::{Migrator, MigrationInfo, MigrationStatus};

// Re-export sqlx pool for convenience
pub use sqlx::PgPool;

// Embed migrations at compile time
pub use sqlx::migrate::Migrator as SqlxMigrator;

/// Returns the embedded migrator with all migrations.
pub fn migrations() -> SqlxMigrator {
    sqlx::migrate!("./migrations")
}
