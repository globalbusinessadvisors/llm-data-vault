//! Client builder for fluent configuration.

use std::time::Duration;

use crate::auth::AuthProvider;
use crate::error::{Error, Result};

use super::config::{RetryConfig, VaultConfig};
use super::VaultClient;

/// Builder for creating a [`VaultClient`].
///
/// # Example
///
/// ```rust,no_run
/// use vault_sdk::VaultClient;
/// use std::time::Duration;
///
/// let client = VaultClient::builder()
///     .base_url("https://vault.example.com")
///     .api_key("vk_live_xxxxx")
///     .timeout(Duration::from_secs(60))
///     .max_retries(5)
///     .build()?;
/// # Ok::<(), vault_sdk::Error>(())
/// ```
#[derive(Debug, Default)]
pub struct VaultClientBuilder {
    base_url: Option<String>,
    auth: Option<AuthProvider>,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    follow_redirects: Option<bool>,
    max_redirects: Option<usize>,
    user_agent: Option<String>,
    retry: Option<RetryConfig>,
    proxy: Option<String>,
    tls_verify: Option<bool>,
}

impl VaultClientBuilder {
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the base URL of the Vault API.
    ///
    /// This is required and must be called before [`build()`](Self::build).
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Sets the API key for authentication.
    ///
    /// This is mutually exclusive with [`bearer_token()`](Self::bearer_token).
    #[must_use]
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.auth = Some(AuthProvider::api_key(key.into()));
        self
    }

    /// Sets the bearer token for authentication.
    ///
    /// This is mutually exclusive with [`api_key()`](Self::api_key).
    #[must_use]
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.auth = Some(AuthProvider::bearer(token.into()));
        self
    }

    /// Sets a custom authentication provider.
    #[must_use]
    pub fn auth(mut self, auth: AuthProvider) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Sets the request timeout.
    ///
    /// Default: 30 seconds.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the request timeout in seconds.
    #[must_use]
    pub fn timeout_secs(self, secs: u64) -> Self {
        self.timeout(Duration::from_secs(secs))
    }

    /// Sets the connection timeout.
    ///
    /// Default: 10 seconds.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Sets whether to follow redirects.
    ///
    /// Default: true.
    #[must_use]
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = Some(follow);
        self
    }

    /// Sets the maximum number of redirects to follow.
    ///
    /// Default: 10.
    #[must_use]
    pub fn max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = Some(max);
        self
    }

    /// Sets the user agent string.
    #[must_use]
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Sets the retry configuration.
    #[must_use]
    pub fn retry(mut self, retry: RetryConfig) -> Self {
        self.retry = Some(retry);
        self
    }

    /// Sets the maximum number of retries.
    ///
    /// Default: 3.
    #[must_use]
    pub fn max_retries(mut self, max: u32) -> Self {
        self.retry = Some(self.retry.unwrap_or_default().with_max_retries(max));
        self
    }

    /// Disables automatic retries.
    #[must_use]
    pub fn no_retry(mut self) -> Self {
        self.retry = Some(RetryConfig::disabled());
        self
    }

    /// Sets the proxy URL.
    #[must_use]
    pub fn proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Sets whether to verify TLS certificates.
    ///
    /// Default: true.
    ///
    /// # Security Warning
    ///
    /// Disabling TLS verification is insecure and should only be used
    /// for testing purposes with self-signed certificates.
    #[must_use]
    pub fn tls_verify(mut self, verify: bool) -> Self {
        self.tls_verify = Some(verify);
        self
    }

    /// Disables TLS certificate verification.
    ///
    /// # Security Warning
    ///
    /// This is insecure and should only be used for testing.
    #[must_use]
    pub fn danger_accept_invalid_certs(self) -> Self {
        self.tls_verify(false)
    }

    /// Builds the client.
    ///
    /// # Errors
    ///
    /// Returns an error if the base URL is not set.
    pub fn build(self) -> Result<VaultClient> {
        let base_url = self.base_url.ok_or_else(|| {
            Error::config("base_url is required")
        })?;

        let mut config = VaultConfig::new(base_url);

        if let Some(auth) = self.auth {
            config = config.with_auth(auth);
        }

        if let Some(timeout) = self.timeout {
            config = config.with_timeout(timeout);
        }

        if let Some(timeout) = self.connect_timeout {
            config = config.with_connect_timeout(timeout);
        }

        if let Some(follow) = self.follow_redirects {
            config = config.with_follow_redirects(follow);
        }

        if let Some(max) = self.max_redirects {
            config = config.with_max_redirects(max);
        }

        if let Some(user_agent) = self.user_agent {
            config = config.with_user_agent(user_agent);
        }

        if let Some(retry) = self.retry {
            config = config.with_retry(retry);
        }

        if let Some(proxy) = self.proxy {
            config = config.with_proxy(proxy);
        }

        if let Some(verify) = self.tls_verify {
            config = config.with_tls_verify(verify);
        }

        VaultClient::new(config)
    }
}

impl RetryConfig {
    /// Sets the maximum number of retries (builder pattern).
    #[must_use]
    fn with_max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self.enabled = max > 0;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_requires_base_url() {
        let result = VaultClientBuilder::new().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_with_base_url() {
        let result = VaultClientBuilder::new()
            .base_url("http://localhost:8080")
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_with_api_key() {
        let result = VaultClientBuilder::new()
            .base_url("http://localhost:8080")
            .api_key("test-key")
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_with_timeout() {
        let result = VaultClientBuilder::new()
            .base_url("http://localhost:8080")
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(5))
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_with_retry() {
        let result = VaultClientBuilder::new()
            .base_url("http://localhost:8080")
            .max_retries(5)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_no_retry() {
        let result = VaultClientBuilder::new()
            .base_url("http://localhost:8080")
            .no_retry()
            .build();
        assert!(result.is_ok());
    }
}
