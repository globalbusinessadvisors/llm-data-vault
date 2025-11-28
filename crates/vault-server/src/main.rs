//! LLM Data Vault Server
//!
//! Production-ready server binary for LLM Data Vault.

mod config;
mod telemetry;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing::info;

use vault_access::{AbacEngine, Authorizer, PolicyEngine, RbacManager, Role, TokenConfig, TokenManager};
use vault_api::{create_router, state::AppState, handlers::health::init_start_time};
use vault_integration::EventBus;
use vault_storage::{ContentAddress, StorageResult};

use crate::config::ServerConfig;
use crate::telemetry::init_telemetry;

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Load configuration
    let config = ServerConfig::load().context("Failed to load configuration")?;

    // Initialize telemetry
    init_telemetry(&config.telemetry)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting LLM Data Vault Server"
    );

    // Initialize start time for health checks
    init_start_time();

    // Build application state
    let state = build_app_state(&config).await?;

    // Create router
    let app = create_router(state);

    // Bind server
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .context("Invalid server address")?;

    info!(address = %addr, "Server listening");

    // Create server with graceful shutdown
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error")?;

    info!("Server shut down gracefully");
    Ok(())
}

/// Builds the application state.
async fn build_app_state(config: &ServerConfig) -> Result<Arc<AppState>> {
    // Initialize storage
    let storage = init_storage(config).await?;

    // Initialize token manager
    let token_config = TokenConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        audience: Some(config.jwt_audience.clone()),
        access_token_ttl: (config.token_expiry_hours * 3600) as i64,
        refresh_token_ttl: 86400 * 7, // 7 days
        algorithm: jsonwebtoken::Algorithm::HS256,
    };
    let tokens = Arc::new(TokenManager::new(token_config));

    // Initialize authorizer components
    let rbac = Arc::new(RbacManager::new());
    setup_default_roles(&rbac);

    let abac = Arc::new(AbacEngine::new());
    let policy_engine = Arc::new(PolicyEngine::new());

    let authorizer = Arc::new(Authorizer::new(
        rbac,
        abac,
        policy_engine,
        tokens.clone(),
    ));

    // Initialize event bus
    let events = Arc::new(EventBus::default_config());

    // Build app state
    let state = AppState::builder()
        .storage(storage)
        .tokens(tokens)
        .authorizer(authorizer)
        .events(events)
        .config(vault_api::state::AppConfig {
            service_name: config.service_name.clone(),
            api_version: "v1".to_string(),
            debug: config.debug,
            max_body_size: config.max_body_size,
            request_timeout_seconds: config.request_timeout_seconds,
            rate_limit_rps: config.rate_limit_rps,
            rate_limit_burst: config.rate_limit_burst,
            enable_metrics: config.telemetry.enable_metrics,
            enable_tracing: config.telemetry.enable_tracing,
            cors_origins: config.cors_origins.clone(),
        })
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build app state: {}", e))?;

    Ok(Arc::new(state))
}

/// Initializes storage backend.
async fn init_storage(_config: &ServerConfig) -> Result<Arc<dyn vault_api::state::ContentStoreAccess>> {
    // For now, use a simple in-memory storage implementation
    // In production, use S3 or filesystem based on config
    Ok(Arc::new(SimpleContentStore::new()))
}

/// Simple in-memory content store for testing.
struct SimpleContentStore {
    data: parking_lot::RwLock<std::collections::HashMap<String, Vec<u8>>>,
}

impl SimpleContentStore {
    fn new() -> Self {
        Self {
            data: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }
}

impl vault_api::state::ContentStoreAccess for SimpleContentStore {
    fn store(&self, content: &[u8]) -> StorageResult<ContentAddress> {
        let hash = blake3::hash(content).to_hex().to_string();
        let address = ContentAddress::new(vault_storage::HashAlgorithm::Blake3, hash.clone());
        self.data.write().insert(hash, content.to_vec());
        Ok(address)
    }

    fn get(&self, address: &ContentAddress) -> StorageResult<Vec<u8>> {
        self.data
            .read()
            .get(&address.hash)
            .cloned()
            .ok_or_else(|| vault_storage::StorageError::NotFound(address.hash.clone()))
    }

    fn exists(&self, address: &ContentAddress) -> StorageResult<bool> {
        Ok(self.data.read().contains_key(&address.hash))
    }

    fn delete(&self, address: &ContentAddress) -> StorageResult<()> {
        self.data.write().remove(&address.hash);
        Ok(())
    }
}

/// Sets up default RBAC roles.
fn setup_default_roles(rbac: &RbacManager) {
    // Admin role (system role)
    let admin_role = Role::system("admin", "Administrator")
        .with_description("Administrator with full access")
        .with_permission("*:*");
    rbac.add_role(admin_role);

    // Data admin role
    let data_admin = Role::new("data-admin", "Data Administrator")
        .with_description("Data administrator with dataset management access")
        .with_permission("datasets:*")
        .with_permission("records:*");
    rbac.add_role(data_admin);

    // Data analyst role
    let analyst = Role::new("data-analyst", "Data Analyst")
        .with_description("Data analyst with read access")
        .with_permission("datasets:read")
        .with_permission("datasets:list")
        .with_permission("records:read")
        .with_permission("records:list");
    rbac.add_role(analyst);

    // Auditor role
    let auditor = Role::new("auditor", "Auditor")
        .with_description("Auditor with read-only access")
        .with_permission("*:read")
        .with_permission("*:list")
        .with_permission("audit:*");
    rbac.add_role(auditor);

    info!("Default RBAC roles configured");
}

/// Shutdown signal handler.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down");
        }
        _ = terminate => {
            info!("Received SIGTERM, shutting down");
        }
    }
}
