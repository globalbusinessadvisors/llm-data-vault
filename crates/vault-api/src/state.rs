//! Application state.

use std::sync::Arc;
use vault_access::{Authorizer, TokenManager};
use vault_integration::EventBus;
use vault_storage::ContentStore;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    /// Content store.
    pub storage: Arc<dyn ContentStoreAccess>,
    /// Token manager.
    pub tokens: Arc<TokenManager>,
    /// Authorizer.
    pub authorizer: Arc<Authorizer>,
    /// Event bus.
    pub events: Arc<EventBus>,
    /// Application configuration.
    pub config: AppConfig,
}

/// Trait for accessing content store (allows mocking).
pub trait ContentStoreAccess: Send + Sync {
    /// Stores content and returns the address.
    fn store(&self, content: &[u8]) -> vault_storage::StorageResult<vault_storage::ContentAddress>;

    /// Retrieves content by address.
    fn get(&self, address: &vault_storage::ContentAddress) -> vault_storage::StorageResult<Vec<u8>>;

    /// Checks if content exists.
    fn exists(&self, address: &vault_storage::ContentAddress) -> vault_storage::StorageResult<bool>;

    /// Deletes content.
    fn delete(&self, address: &vault_storage::ContentAddress) -> vault_storage::StorageResult<()>;
}

/// Application configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Service name.
    pub service_name: String,
    /// API version.
    pub api_version: String,
    /// Enable debug mode.
    pub debug: bool,
    /// Max request body size.
    pub max_body_size: usize,
    /// Request timeout in seconds.
    pub request_timeout_seconds: u64,
    /// Rate limit requests per second.
    pub rate_limit_rps: u32,
    /// Rate limit burst size.
    pub rate_limit_burst: u32,
    /// Enable metrics.
    pub enable_metrics: bool,
    /// Enable tracing.
    pub enable_tracing: bool,
    /// CORS allowed origins.
    pub cors_origins: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            service_name: "llm-data-vault".to_string(),
            api_version: "v1".to_string(),
            debug: false,
            max_body_size: 10 * 1024 * 1024, // 10MB
            request_timeout_seconds: 30,
            rate_limit_rps: 100,
            rate_limit_burst: 200,
            enable_metrics: true,
            enable_tracing: true,
            cors_origins: vec!["*".to_string()],
        }
    }
}

impl AppState {
    /// Creates a new application state builder.
    pub fn builder() -> AppStateBuilder {
        AppStateBuilder::new()
    }
}

/// Builder for AppState.
pub struct AppStateBuilder {
    storage: Option<Arc<dyn ContentStoreAccess>>,
    tokens: Option<Arc<TokenManager>>,
    authorizer: Option<Arc<Authorizer>>,
    events: Option<Arc<EventBus>>,
    config: AppConfig,
}

impl AppStateBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {
            storage: None,
            tokens: None,
            authorizer: None,
            events: None,
            config: AppConfig::default(),
        }
    }

    /// Sets the storage.
    pub fn storage(mut self, storage: Arc<dyn ContentStoreAccess>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Sets the token manager.
    pub fn tokens(mut self, tokens: Arc<TokenManager>) -> Self {
        self.tokens = Some(tokens);
        self
    }

    /// Sets the authorizer.
    pub fn authorizer(mut self, authorizer: Arc<Authorizer>) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Sets the event bus.
    pub fn events(mut self, events: Arc<EventBus>) -> Self {
        self.events = Some(events);
        self
    }

    /// Sets the configuration.
    pub fn config(mut self, config: AppConfig) -> Self {
        self.config = config;
        self
    }

    /// Builds the AppState.
    pub fn build(self) -> Result<AppState, &'static str> {
        Ok(AppState {
            storage: self.storage.ok_or("storage is required")?,
            tokens: self.tokens.ok_or("tokens is required")?,
            authorizer: self.authorizer.ok_or("authorizer is required")?,
            events: self.events.ok_or("events is required")?,
            config: self.config,
        })
    }
}

impl Default for AppStateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Request context extracted from the request.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Request ID.
    pub request_id: String,
    /// User ID (if authenticated).
    pub user_id: Option<String>,
    /// Tenant ID (if multi-tenant).
    pub tenant_id: Option<String>,
    /// Request path.
    pub path: String,
    /// Request method.
    pub method: String,
    /// Start time.
    pub start_time: std::time::Instant,
}

impl RequestContext {
    /// Creates a new request context.
    pub fn new(request_id: impl Into<String>, path: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            user_id: None,
            tenant_id: None,
            path: path.into(),
            method: method.into(),
            start_time: std::time::Instant::now(),
        }
    }

    /// Sets the user ID.
    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Sets the tenant ID.
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Returns the elapsed time in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}
