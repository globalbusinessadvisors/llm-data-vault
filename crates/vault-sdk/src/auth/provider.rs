//! Authentication providers.

use async_trait::async_trait;
use reqwest::RequestBuilder;
use secrecy::{ExposeSecret, SecretString};

use super::Authenticator;
use crate::error::Result;

/// API key authentication.
#[derive(Clone)]
pub struct ApiKeyAuth {
    api_key: SecretString,
    header_name: String,
}

impl ApiKeyAuth {
    /// Creates a new API key authenticator.
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: SecretString::new(api_key.into()),
            header_name: "X-Api-Key".to_string(),
        }
    }

    /// Creates API key auth with a custom header name.
    #[must_use]
    pub fn with_header(api_key: impl Into<String>, header: impl Into<String>) -> Self {
        Self {
            api_key: SecretString::new(api_key.into()),
            header_name: header.into(),
        }
    }
}

#[async_trait]
impl Authenticator for ApiKeyAuth {
    async fn authenticate(&self, request: RequestBuilder) -> Result<RequestBuilder> {
        Ok(request.header(&self.header_name, self.api_key.expose_secret()))
    }

    fn needs_refresh(&self) -> bool {
        false // API keys don't need refresh
    }

    async fn refresh(&self) -> Result<()> {
        Ok(()) // No-op for API keys
    }
}

impl std::fmt::Debug for ApiKeyAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyAuth")
            .field("header_name", &self.header_name)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

/// Bearer token authentication.
#[derive(Clone)]
pub struct BearerAuth {
    token: SecretString,
}

impl BearerAuth {
    /// Creates a new bearer token authenticator.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: SecretString::new(token.into()),
        }
    }
}

#[async_trait]
impl Authenticator for BearerAuth {
    async fn authenticate(&self, request: RequestBuilder) -> Result<RequestBuilder> {
        Ok(request.bearer_auth(self.token.expose_secret()))
    }

    fn needs_refresh(&self) -> bool {
        false // Static token doesn't refresh
    }

    async fn refresh(&self) -> Result<()> {
        Ok(())
    }
}

impl std::fmt::Debug for BearerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerAuth")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// No authentication.
#[derive(Debug, Clone, Default)]
pub struct NoAuth;

impl NoAuth {
    /// Creates a new no-auth provider.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Authenticator for NoAuth {
    async fn authenticate(&self, request: RequestBuilder) -> Result<RequestBuilder> {
        Ok(request)
    }

    fn needs_refresh(&self) -> bool {
        false
    }

    async fn refresh(&self) -> Result<()> {
        Ok(())
    }
}

/// Enum wrapper for different auth providers.
#[derive(Clone)]
pub enum AuthProvider {
    /// API key authentication.
    ApiKey(ApiKeyAuth),
    /// Bearer token authentication.
    Bearer(BearerAuth),
    /// No authentication.
    None(NoAuth),
}

impl AuthProvider {
    /// Creates API key authentication.
    #[must_use]
    pub fn api_key(key: impl Into<String>) -> Self {
        Self::ApiKey(ApiKeyAuth::new(key))
    }

    /// Creates bearer token authentication.
    #[must_use]
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer(BearerAuth::new(token))
    }

    /// Creates no authentication.
    #[must_use]
    pub fn none() -> Self {
        Self::None(NoAuth::new())
    }
}

impl Default for AuthProvider {
    fn default() -> Self {
        Self::None(NoAuth::new())
    }
}

#[async_trait]
impl Authenticator for AuthProvider {
    async fn authenticate(&self, request: RequestBuilder) -> Result<RequestBuilder> {
        match self {
            Self::ApiKey(auth) => auth.authenticate(request).await,
            Self::Bearer(auth) => auth.authenticate(request).await,
            Self::None(auth) => auth.authenticate(request).await,
        }
    }

    fn needs_refresh(&self) -> bool {
        match self {
            Self::ApiKey(auth) => auth.needs_refresh(),
            Self::Bearer(auth) => auth.needs_refresh(),
            Self::None(auth) => auth.needs_refresh(),
        }
    }

    async fn refresh(&self) -> Result<()> {
        match self {
            Self::ApiKey(auth) => auth.refresh().await,
            Self::Bearer(auth) => auth.refresh().await,
            Self::None(auth) => auth.refresh().await,
        }
    }
}

impl std::fmt::Debug for AuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(auth) => write!(f, "AuthProvider::ApiKey({auth:?})"),
            Self::Bearer(auth) => write!(f, "AuthProvider::Bearer({auth:?})"),
            Self::None(auth) => write!(f, "AuthProvider::None({auth:?})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_debug_redacts() {
        let auth = ApiKeyAuth::new("secret-key");
        let debug = format!("{auth:?}");
        assert!(!debug.contains("secret-key"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_bearer_debug_redacts() {
        let auth = BearerAuth::new("secret-token");
        let debug = format!("{auth:?}");
        assert!(!debug.contains("secret-token"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[tokio::test]
    async fn test_no_auth_passthrough() {
        let auth = NoAuth::new();
        let client = reqwest::Client::new();
        let request = client.get("http://example.com");

        let result = auth.authenticate(request).await;
        assert!(result.is_ok());
    }
}
