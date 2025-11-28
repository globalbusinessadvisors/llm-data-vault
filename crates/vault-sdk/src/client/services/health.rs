//! Health check service.

use std::sync::Arc;

use crate::error::Result;
use crate::models::HealthStatus;

use super::super::http::HttpClient;

/// Service for health checks.
#[derive(Clone)]
pub struct HealthService {
    http: Arc<HttpClient>,
}

impl HealthService {
    /// Creates a new health service.
    pub(crate) fn new(http: Arc<HttpClient>) -> Self {
        Self { http }
    }

    /// Checks the health of the API.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let health = client.health().check().await?;
    ///
    /// match health.status {
    ///     vault_sdk::ServiceStatus::Healthy => println!("All systems go!"),
    ///     vault_sdk::ServiceStatus::Degraded => println!("Some issues detected"),
    ///     vault_sdk::ServiceStatus::Unhealthy => println!("System is unhealthy"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn check(&self) -> Result<HealthStatus> {
        self.http.get("/api/v1/health").await
    }

    /// Checks if the API is alive (simple ping).
    ///
    /// This is a lightweight check that doesn't verify component health.
    pub async fn ping(&self) -> Result<bool> {
        match self.http.get::<serde_json::Value>("/api/v1/health/ping").await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Checks readiness for accepting traffic.
    pub async fn ready(&self) -> Result<bool> {
        match self.http.get::<serde_json::Value>("/api/v1/health/ready").await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl std::fmt::Debug for HealthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthService").finish_non_exhaustive()
    }
}
