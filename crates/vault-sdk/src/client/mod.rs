//! Vault API client implementation.
//!
//! This module provides the main client for interacting with the Vault API.

mod builder;
mod config;
mod http;
mod services;

pub use builder::VaultClientBuilder;
pub use config::VaultConfig;

use std::sync::Arc;

use crate::auth::{AuthProvider, Authenticator};
use crate::error::Result;

use self::http::HttpClient;
use self::services::{
    DatasetsService, RecordsService, PiiService, WebhooksService,
    AuthService, ApiKeysService, HealthService,
};

/// The main client for interacting with the Vault API.
///
/// Use [`VaultClient::builder()`] to create a new client instance.
///
/// # Example
///
/// ```rust,no_run
/// use vault_sdk::VaultClient;
///
/// #[tokio::main]
/// async fn main() -> Result<(), vault_sdk::Error> {
///     let client = VaultClient::builder()
///         .base_url("https://vault.example.com")
///         .api_key("your-api-key")
///         .build()?;
///
///     // Check health
///     let health = client.health().check().await?;
///     println!("Status: {}", health.status);
///
///     // List datasets
///     let datasets = client.datasets().list().await?;
///     for ds in datasets.items {
///         println!("Dataset: {}", ds.name);
///     }
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct VaultClient {
    http: Arc<HttpClient>,
    config: Arc<VaultConfig>,
}

impl VaultClient {
    /// Creates a new client builder.
    #[must_use]
    pub fn builder() -> VaultClientBuilder {
        VaultClientBuilder::new()
    }

    /// Creates a new client from configuration.
    pub fn new(config: VaultConfig) -> Result<Self> {
        let http = HttpClient::new(&config)?;
        Ok(Self {
            http: Arc::new(http),
            config: Arc::new(config),
        })
    }

    /// Creates a new client with the specified base URL and authentication.
    pub fn with_auth(base_url: &str, auth: impl Into<AuthProvider>) -> Result<Self> {
        let config = VaultConfig::new(base_url).with_auth(auth.into());
        Self::new(config)
    }

    /// Returns the current configuration.
    #[must_use]
    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    /// Returns the base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    // ========================================================================
    // Service accessors
    // ========================================================================

    /// Returns the health service for health checks.
    #[must_use]
    pub fn health(&self) -> HealthService {
        HealthService::new(Arc::clone(&self.http))
    }

    /// Returns the authentication service.
    #[must_use]
    pub fn auth(&self) -> AuthService {
        AuthService::new(Arc::clone(&self.http))
    }

    /// Returns the API keys service.
    #[must_use]
    pub fn api_keys(&self) -> ApiKeysService {
        ApiKeysService::new(Arc::clone(&self.http))
    }

    /// Returns the datasets service.
    #[must_use]
    pub fn datasets(&self) -> DatasetsService {
        DatasetsService::new(Arc::clone(&self.http))
    }

    /// Returns the records service for a specific dataset.
    #[must_use]
    pub fn records(&self, dataset_id: impl Into<String>) -> RecordsService {
        RecordsService::new(Arc::clone(&self.http), dataset_id.into())
    }

    /// Returns the PII detection and anonymization service.
    #[must_use]
    pub fn pii(&self) -> PiiService {
        PiiService::new(Arc::clone(&self.http))
    }

    /// Returns the webhooks service.
    #[must_use]
    pub fn webhooks(&self) -> WebhooksService {
        WebhooksService::new(Arc::clone(&self.http))
    }
}

impl std::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultClient")
            .field("base_url", &self.config.base_url)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creates_client() {
        let result = VaultClient::builder()
            .base_url("http://localhost:8080")
            .build();

        assert!(result.is_ok());
        let client = result.expect("Failed to build client");
        assert_eq!(client.base_url(), "http://localhost:8080");
    }

    #[test]
    fn test_client_debug_shows_base_url() {
        let client = VaultClient::builder()
            .base_url("http://localhost:8080")
            .build()
            .expect("Failed to build client");

        let debug = format!("{client:?}");
        assert!(debug.contains("localhost:8080"));
    }
}
