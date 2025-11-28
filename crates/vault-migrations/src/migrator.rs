//! Migration runner and management.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::{info, warn, error};

use crate::error::{MigrationError, Result};

/// Migration status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Migration is pending (not yet applied).
    Pending,
    /// Migration has been applied.
    Applied,
    /// Migration was applied but checksum doesn't match.
    Modified,
}

impl std::fmt::Display for MigrationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Applied => write!(f, "applied"),
            Self::Modified => write!(f, "modified"),
        }
    }
}

/// Information about a migration.
#[derive(Debug, Clone)]
pub struct MigrationInfo {
    /// Migration version (timestamp).
    pub version: i64,
    /// Migration description.
    pub description: String,
    /// Migration status.
    pub status: MigrationStatus,
    /// When the migration was applied (if applied).
    pub applied_at: Option<DateTime<Utc>>,
    /// Execution time in milliseconds (if applied).
    pub execution_time_ms: Option<i64>,
    /// Checksum of the migration.
    pub checksum: Option<Vec<u8>>,
}

/// Database migrator.
pub struct Migrator {
    pool: PgPool,
}

impl Migrator {
    /// Creates a new migrator.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Runs all pending migrations.
    pub async fn run(&self) -> Result<()> {
        info!("Running database migrations");

        let migrator = crate::migrations();

        migrator.run(&self.pool).await.map_err(|e| {
            error!("Migration failed: {}", e);
            MigrationError::migration(e.to_string(), None)
        })?;

        info!("Migrations completed successfully");
        Ok(())
    }

    /// Reverts the last applied migration.
    pub async fn revert(&self) -> Result<()> {
        info!("Reverting last migration");

        let migrator = crate::migrations();

        migrator.undo(&self.pool, 1).await.map_err(|e| {
            error!("Migration revert failed: {}", e);
            MigrationError::migration(e.to_string(), None)
        })?;

        info!("Migration reverted successfully");
        Ok(())
    }

    /// Reverts all migrations.
    pub async fn revert_all(&self) -> Result<()> {
        info!("Reverting all migrations");

        let migrator = crate::migrations();
        let migrations = migrator.iter();
        let count = migrations.count();

        migrator.undo(&self.pool, count as i64).await.map_err(|e| {
            error!("Migration revert failed: {}", e);
            MigrationError::migration(e.to_string(), None)
        })?;

        info!("All migrations reverted");
        Ok(())
    }

    /// Lists all migrations and their status.
    pub async fn list(&self) -> Result<Vec<MigrationInfo>> {
        let migrator = crate::migrations();

        // Get applied migrations from database
        let applied = self.get_applied_migrations().await?;

        let mut result = Vec::new();

        for migration in migrator.iter() {
            let version = migration.version;
            let description = migration.description.to_string();
            let checksum = migration.checksum.to_vec();

            let (status, applied_at, execution_time_ms) = if let Some(info) = applied.iter().find(|a| a.version == version) {
                let status = if info.checksum == checksum {
                    MigrationStatus::Applied
                } else {
                    MigrationStatus::Modified
                };
                (status, Some(info.applied_at), info.execution_time_ms)
            } else {
                (MigrationStatus::Pending, None, None)
            };

            result.push(MigrationInfo {
                version,
                description,
                status,
                applied_at,
                execution_time_ms,
                checksum: Some(checksum),
            });
        }

        // Sort by version
        result.sort_by_key(|m| m.version);

        Ok(result)
    }

    /// Returns the current migration version.
    pub async fn current_version(&self) -> Result<Option<i64>> {
        let applied = self.get_applied_migrations().await?;
        Ok(applied.into_iter().map(|m| m.version).max())
    }

    /// Returns pending migrations count.
    pub async fn pending_count(&self) -> Result<usize> {
        let list = self.list().await?;
        Ok(list.iter().filter(|m| m.status == MigrationStatus::Pending).count())
    }

    /// Checks if the database is up to date.
    pub async fn is_up_to_date(&self) -> Result<bool> {
        Ok(self.pending_count().await? == 0)
    }

    /// Validates migrations (checks for modified migrations).
    pub async fn validate(&self) -> Result<()> {
        let list = self.list().await?;
        let modified: Vec<_> = list.into_iter()
            .filter(|m| m.status == MigrationStatus::Modified)
            .collect();

        if !modified.is_empty() {
            warn!("Found {} modified migrations", modified.len());
            return Err(MigrationError::checksum_mismatch(
                modified[0].version,
                "Migration files have been modified after being applied".to_string(),
            ));
        }

        Ok(())
    }

    /// Gets applied migrations from the database.
    async fn get_applied_migrations(&self) -> Result<Vec<AppliedMigration>> {
        // First ensure the migrations table exists
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS _sqlx_migrations (
                version BIGINT PRIMARY KEY,
                description TEXT NOT NULL,
                installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                success BOOLEAN NOT NULL,
                checksum BYTEA NOT NULL,
                execution_time BIGINT NOT NULL
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, AppliedMigrationRow>(
            r#"
            SELECT version, description, installed_on, checksum, execution_time
            FROM _sqlx_migrations
            WHERE success = true
            ORDER BY version
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| AppliedMigration {
            version: r.version,
            description: r.description,
            applied_at: r.installed_on,
            checksum: r.checksum,
            execution_time_ms: Some(r.execution_time),
        }).collect())
    }
}

#[derive(sqlx::FromRow)]
struct AppliedMigrationRow {
    version: i64,
    description: String,
    installed_on: DateTime<Utc>,
    checksum: Vec<u8>,
    execution_time: i64,
}

struct AppliedMigration {
    version: i64,
    #[allow(dead_code)]
    description: String,
    applied_at: DateTime<Utc>,
    checksum: Vec<u8>,
    execution_time_ms: Option<i64>,
}
