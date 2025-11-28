//! API keys service.

use std::sync::Arc;

use uuid::Uuid;

use crate::error::Result;
use crate::models::{ApiKey, ApiKeyCreate, ApiKeyCreateResponse, ApiKeyList, Pagination};

use super::super::http::HttpClient;

/// Service for managing API keys.
#[derive(Clone)]
pub struct ApiKeysService {
    http: Arc<HttpClient>,
}

impl ApiKeysService {
    /// Creates a new API keys service.
    pub(crate) fn new(http: Arc<HttpClient>) -> Self {
        Self { http }
    }

    /// Lists all API keys.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::VaultClient;
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let keys = client.api_keys().list().await?;
    ///
    /// for key in keys.items {
    ///     println!("{}: {} ({})", key.name, key.prefix, if key.active { "active" } else { "inactive" });
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list(&self) -> Result<ApiKeyList> {
        self.http.get("/api/v1/api-keys").await
    }

    /// Lists API keys with pagination.
    pub async fn list_with_pagination(&self, pagination: &Pagination) -> Result<ApiKeyList> {
        let url = format!(
            "/api/v1/api-keys?limit={}&offset={}",
            pagination.limit.unwrap_or(20),
            pagination.offset.unwrap_or(0)
        );
        self.http.get(&url).await
    }

    /// Gets an API key by ID.
    ///
    /// Note: The full secret is never returned; only the prefix is available.
    pub async fn get(&self, id: impl AsRef<str>) -> Result<ApiKey> {
        let url = format!("/api/v1/api-keys/{}", id.as_ref());
        self.http.get(&url).await
    }

    /// Creates a new API key.
    ///
    /// # Important
    ///
    /// The returned secret is only shown once. Store it securely.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use vault_sdk::{VaultClient, ApiKeyCreate};
    /// # async fn example(client: VaultClient) -> Result<(), vault_sdk::Error> {
    /// let request = ApiKeyCreate::new("CI/CD Key", vec!["datasets:read".into(), "records:read".into()]);
    ///
    /// let response = client.api_keys().create(&request).await?;
    ///
    /// println!("Key ID: {}", response.api_key.id);
    /// println!("Secret (save this!): {}", response.secret);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create(&self, request: &ApiKeyCreate) -> Result<ApiKeyCreateResponse> {
        self.http.post("/api/v1/api-keys", request).await
    }

    /// Revokes (deletes) an API key.
    ///
    /// This action is irreversible.
    pub async fn revoke(&self, id: impl AsRef<str>) -> Result<()> {
        let url = format!("/api/v1/api-keys/{}", id.as_ref());
        self.http.delete(&url).await
    }

    /// Rotates an API key, generating a new secret.
    ///
    /// The old key remains valid for a grace period.
    ///
    /// # Important
    ///
    /// The returned secret is only shown once. Store it securely.
    pub async fn rotate(&self, id: impl AsRef<str>) -> Result<ApiKeyCreateResponse> {
        let url = format!("/api/v1/api-keys/{}/rotate", id.as_ref());
        self.http.post(&url, &()).await
    }

    /// Enables a disabled API key.
    pub async fn enable(&self, id: impl AsRef<str>) -> Result<ApiKey> {
        let url = format!("/api/v1/api-keys/{}/enable", id.as_ref());
        self.http.post(&url, &()).await
    }

    /// Disables an API key without deleting it.
    pub async fn disable(&self, id: impl AsRef<str>) -> Result<ApiKey> {
        let url = format!("/api/v1/api-keys/{}/disable", id.as_ref());
        self.http.post(&url, &()).await
    }
}

impl std::fmt::Debug for ApiKeysService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeysService").finish_non_exhaustive()
    }
}
