//! Token management and auto-refresh.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::RwLock;
use reqwest::RequestBuilder;
use secrecy::{ExposeSecret, SecretString};

use super::Authenticator;
use crate::error::{Error, Result};

/// Callback for refreshing tokens.
#[async_trait]
pub trait TokenRefresher: Send + Sync {
    /// Refresh the access token.
    async fn refresh_token(&self, refresh_token: &str) -> Result<TokenData>;
}

/// Token data.
#[derive(Clone)]
pub struct TokenData {
    /// Access token.
    pub access_token: SecretString,
    /// Refresh token (optional).
    pub refresh_token: Option<SecretString>,
    /// When the access token expires.
    pub expires_at: Option<Instant>,
}

impl TokenData {
    /// Creates new token data.
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            access_token: SecretString::new(access_token.into()),
            refresh_token: None,
            expires_at: None,
        }
    }

    /// Sets the refresh token.
    #[must_use]
    pub fn with_refresh_token(mut self, token: impl Into<String>) -> Self {
        self.refresh_token = Some(SecretString::new(token.into()));
        self
    }

    /// Sets expiration.
    #[must_use]
    pub fn with_expires_in(mut self, seconds: u64) -> Self {
        self.expires_at = Some(Instant::now() + Duration::from_secs(seconds));
        self
    }

    /// Checks if the token is expired or about to expire.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| {
                // Refresh 30 seconds before actual expiration
                let buffer = Duration::from_secs(30);
                Instant::now() + buffer >= exp
            })
            .unwrap_or(false)
    }
}

/// Manages tokens with auto-refresh capability.
pub struct TokenManager {
    token: Arc<RwLock<TokenData>>,
    refresher: Option<Arc<dyn TokenRefresher>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl TokenManager {
    /// Creates a new token manager with static token.
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            token: Arc::new(RwLock::new(TokenData::new(access_token))),
            refresher: None,
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Creates a token manager with refresh capability.
    pub fn with_refresh(
        access_token: impl Into<String>,
        refresh_token: impl Into<String>,
        expires_in: u64,
        refresher: Arc<dyn TokenRefresher>,
    ) -> Self {
        let token_data = TokenData::new(access_token)
            .with_refresh_token(refresh_token)
            .with_expires_in(expires_in);

        Self {
            token: Arc::new(RwLock::new(token_data)),
            refresher: Some(refresher),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// Gets the current access token.
    pub fn access_token(&self) -> String {
        self.token.read().access_token.expose_secret().to_string()
    }

    /// Updates the token data.
    pub fn update_token(&self, token_data: TokenData) {
        *self.token.write() = token_data;
    }

    /// Performs token refresh if needed.
    async fn do_refresh(&self) -> Result<()> {
        // Acquire lock to prevent concurrent refreshes
        let _lock = self.refresh_lock.lock().await;

        // Double-check after acquiring lock
        if !self.token.read().is_expired() {
            return Ok(());
        }

        let refresher = self.refresher.as_ref().ok_or_else(|| {
            Error::unauthorized("Token expired and no refresher configured")
        })?;

        let refresh_token = self
            .token
            .read()
            .refresh_token
            .as_ref()
            .map(|t| t.expose_secret().to_string())
            .ok_or_else(|| Error::unauthorized("No refresh token available"))?;

        let new_token = refresher.refresh_token(&refresh_token).await?;
        *self.token.write() = new_token;

        Ok(())
    }
}

impl Clone for TokenManager {
    fn clone(&self) -> Self {
        Self {
            token: Arc::clone(&self.token),
            refresher: self.refresher.clone(),
            refresh_lock: Arc::clone(&self.refresh_lock),
        }
    }
}

#[async_trait]
impl Authenticator for TokenManager {
    async fn authenticate(&self, request: RequestBuilder) -> Result<RequestBuilder> {
        // Refresh if needed before using
        if self.needs_refresh() {
            self.refresh().await?;
        }

        let token = self.access_token();
        Ok(request.bearer_auth(token))
    }

    fn needs_refresh(&self) -> bool {
        self.token.read().is_expired()
    }

    async fn refresh(&self) -> Result<()> {
        self.do_refresh().await
    }
}

impl std::fmt::Debug for TokenManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenManager")
            .field("has_refresh_token", &self.token.read().refresh_token.is_some())
            .field("has_refresher", &self.refresher.is_some())
            .field("is_expired", &self.token.read().is_expired())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_data_expiration() {
        let token = TokenData::new("test").with_expires_in(0);
        assert!(token.is_expired());

        let token = TokenData::new("test").with_expires_in(3600);
        assert!(!token.is_expired());
    }

    #[test]
    fn test_token_manager_access() {
        let manager = TokenManager::new("my-token");
        assert_eq!(manager.access_token(), "my-token");
    }

    #[tokio::test]
    async fn test_token_manager_authenticate() {
        let manager = TokenManager::new("test-token");
        let client = reqwest::Client::new();
        let request = client.get("http://example.com");

        let result = manager.authenticate(request).await;
        assert!(result.is_ok());
    }
}
