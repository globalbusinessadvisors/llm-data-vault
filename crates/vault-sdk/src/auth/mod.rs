//! Authentication handling for the Vault SDK.
//!
//! This module provides different authentication methods for the SDK client.

mod provider;
mod token;

pub use provider::{AuthProvider, ApiKeyAuth, BearerAuth, NoAuth};
pub use token::{TokenManager, TokenRefresher};

use async_trait::async_trait;
use reqwest::RequestBuilder;

use crate::error::Result;

/// Trait for authentication providers.
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Apply authentication to a request.
    async fn authenticate(&self, request: RequestBuilder) -> Result<RequestBuilder>;

    /// Check if authentication needs refresh.
    fn needs_refresh(&self) -> bool;

    /// Refresh authentication if needed.
    async fn refresh(&self) -> Result<()>;
}
