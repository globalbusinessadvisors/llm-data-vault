//! Test server setup utilities.

use axum::Router;
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use vault_access::{Authorizer, RbacManager, AbacEngine, PolicyEngine, TokenManager, TokenConfig, Role, Permission};
use vault_integration::EventBus;
use vault_storage::{ContentAddress, StorageResult, StorageError};
use vault_api::{AppState, create_router};
use vault_api::state::{AppConfig, ContentStoreAccess};

/// In-memory content store for testing.
#[derive(Debug, Default)]
pub struct TestContentStore {
    data: RwLock<HashMap<String, Vec<u8>>>,
}

impl TestContentStore {
    /// Creates a new test content store.
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the number of stored items.
    pub fn len(&self) -> usize {
        self.data.read().len()
    }

    /// Checks if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.data.read().is_empty()
    }

    /// Clears all stored content.
    pub fn clear(&self) {
        self.data.write().clear();
    }
}

impl ContentStoreAccess for TestContentStore {
    fn store(&self, content: &[u8]) -> StorageResult<ContentAddress> {
        let hash = blake3::hash(content);
        let address = ContentAddress::new(hash.to_hex().to_string());
        self.data.write().insert(address.to_string(), content.to_vec());
        Ok(address)
    }

    fn get(&self, address: &ContentAddress) -> StorageResult<Vec<u8>> {
        self.data
            .read()
            .get(&address.to_string())
            .cloned()
            .ok_or_else(|| StorageError::NotFound(address.to_string()))
    }

    fn exists(&self, address: &ContentAddress) -> StorageResult<bool> {
        Ok(self.data.read().contains_key(&address.to_string()))
    }

    fn delete(&self, address: &ContentAddress) -> StorageResult<()> {
        self.data.write().remove(&address.to_string());
        Ok(())
    }
}

/// Test server configuration.
#[derive(Debug, Clone)]
pub struct TestServerConfig {
    /// JWT secret for testing.
    pub jwt_secret: String,
    /// Enable rate limiting.
    pub rate_limiting: bool,
    /// Enable auth.
    pub auth_enabled: bool,
    /// Test users to pre-create.
    pub users: Vec<TestUserConfig>,
}

impl Default for TestServerConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test_jwt_secret_at_least_32_characters_long".to_string(),
            rate_limiting: false,
            auth_enabled: true,
            users: vec![],
        }
    }
}

/// Test user configuration.
#[derive(Debug, Clone)]
pub struct TestUserConfig {
    pub id: String,
    pub email: String,
    pub roles: Vec<String>,
}

/// Creates a test application with default configuration.
pub fn create_test_app() -> Router {
    create_test_app_with_config(TestServerConfig::default())
}

/// Creates a test application with custom configuration.
pub fn create_test_app_with_config(config: TestServerConfig) -> Router {
    let state = create_test_state(config);
    create_router(state)
}

/// Creates a test application state.
pub fn create_test_state(config: TestServerConfig) -> Arc<AppState> {
    // Create token manager
    let token_config = TokenConfig {
        secret: config.jwt_secret.clone(),
        issuer: "test".to_string(),
        audience: Some("test".to_string()),
        access_token_ttl: 3600,
        refresh_token_ttl: 86400,
        algorithm: jsonwebtoken::Algorithm::HS256,
    };
    let tokens = Arc::new(TokenManager::new(token_config));

    // Create storage
    let storage: Arc<dyn ContentStoreAccess> = Arc::new(TestContentStore::new());

    // Create RBAC manager with default roles
    let rbac = create_test_rbac();

    // Create ABAC engine
    let abac = AbacEngine::new();

    // Create policy engine
    let policy_engine = PolicyEngine::new();

    // Create authorizer
    let authorizer = Arc::new(Authorizer::new(rbac, abac, policy_engine, true));

    // Create event bus
    let events = Arc::new(EventBus::new());

    // Create app config
    let app_config = AppConfig {
        service_name: "test-vault".to_string(),
        api_version: "v1".to_string(),
        debug: true,
        max_body_size: 10 * 1024 * 1024,
        request_timeout_seconds: 30,
        rate_limit_rps: if config.rate_limiting { 10 } else { 1000 },
        rate_limit_burst: if config.rate_limiting { 20 } else { 2000 },
        enable_metrics: false,
        enable_tracing: false,
        cors_origins: vec!["*".to_string()],
    };

    Arc::new(
        AppState::builder()
            .storage(storage)
            .tokens(tokens)
            .authorizer(authorizer)
            .events(events)
            .config(app_config)
            .build()
            .expect("Failed to build app state"),
    )
}

/// Creates RBAC manager with test roles.
fn create_test_rbac() -> RbacManager {
    let mut rbac = RbacManager::new();

    // Admin role - full access
    let admin_role = Role::new("admin")
        .with_permission(Permission::new("*", "*"))
        .with_description("Administrator with full access");
    rbac.add_role(admin_role);

    // User role - standard access
    let user_role = Role::new("user")
        .with_permission(Permission::new("dataset", "read"))
        .with_permission(Permission::new("dataset", "create"))
        .with_permission(Permission::new("dataset", "update"))
        .with_permission(Permission::new("record", "read"))
        .with_permission(Permission::new("record", "create"))
        .with_permission(Permission::new("record", "update"))
        .with_description("Standard user access");
    rbac.add_role(user_role);

    // Reader role - read-only access
    let reader_role = Role::new("reader")
        .with_permission(Permission::new("dataset", "read"))
        .with_permission(Permission::new("record", "read"))
        .with_description("Read-only access");
    rbac.add_role(reader_role);

    rbac
}

/// Test application wrapper with helper methods.
pub struct TestApp {
    pub router: Router,
    pub state: Arc<AppState>,
    storage: Arc<TestContentStore>,
}

impl TestApp {
    /// Creates a new test application.
    pub fn new() -> Self {
        Self::with_config(TestServerConfig::default())
    }

    /// Creates a new test application with custom config.
    pub fn with_config(config: TestServerConfig) -> Self {
        let storage = Arc::new(TestContentStore::new());

        // Create token manager
        let token_config = TokenConfig {
            secret: config.jwt_secret.clone(),
            issuer: "test".to_string(),
            audience: Some("test".to_string()),
            access_token_ttl: 3600,
            refresh_token_ttl: 86400,
            algorithm: jsonwebtoken::Algorithm::HS256,
        };
        let tokens = Arc::new(TokenManager::new(token_config));

        // Create authorizer
        let rbac = create_test_rbac();
        let abac = AbacEngine::new();
        let policy_engine = PolicyEngine::new();
        let authorizer = Arc::new(Authorizer::new(rbac, abac, policy_engine, true));

        // Create event bus
        let events = Arc::new(EventBus::new());

        // Create app config
        let app_config = AppConfig {
            service_name: "test-vault".to_string(),
            api_version: "v1".to_string(),
            debug: true,
            max_body_size: 10 * 1024 * 1024,
            request_timeout_seconds: 30,
            rate_limit_rps: if config.rate_limiting { 10 } else { 1000 },
            rate_limit_burst: if config.rate_limiting { 20 } else { 2000 },
            enable_metrics: false,
            enable_tracing: false,
            cors_origins: vec!["*".to_string()],
        };

        let state = Arc::new(
            AppState::builder()
                .storage(storage.clone() as Arc<dyn ContentStoreAccess>)
                .tokens(tokens)
                .authorizer(authorizer)
                .events(events)
                .config(app_config)
                .build()
                .expect("Failed to build app state"),
        );

        let router = create_router(state.clone());

        Self {
            router,
            state,
            storage,
        }
    }

    /// Returns the storage.
    pub fn storage(&self) -> &TestContentStore {
        &self.storage
    }

    /// Clears all stored data.
    pub fn clear_storage(&self) {
        self.storage.clear();
    }

    /// Generates a test JWT token.
    pub fn generate_token(&self, user_id: &str, roles: &[&str]) -> String {
        // For testing, generate a simple token
        // In real tests, use the token manager
        let claims = serde_json::json!({
            "sub": user_id,
            "roles": roles,
            "exp": chrono::Utc::now().timestamp() + 3600,
            "iat": chrono::Utc::now().timestamp(),
            "iss": "test",
            "aud": "test"
        });

        jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(
                "test_jwt_secret_at_least_32_characters_long".as_bytes()
            ),
        )
        .expect("Failed to generate token")
    }

    /// Generates an admin token.
    pub fn admin_token(&self) -> String {
        self.generate_token("admin_user", &["admin"])
    }

    /// Generates a regular user token.
    pub fn user_token(&self) -> String {
        self.generate_token("regular_user", &["user"])
    }

    /// Generates a read-only token.
    pub fn reader_token(&self) -> String {
        self.generate_token("reader_user", &["reader"])
    }
}

impl Default for TestApp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_store() {
        let store = TestContentStore::new();

        // Store content
        let content = b"test content";
        let address = store.store(content).unwrap();

        // Retrieve content
        let retrieved = store.get(&address).unwrap();
        assert_eq!(retrieved, content);

        // Check exists
        assert!(store.exists(&address).unwrap());

        // Delete
        store.delete(&address).unwrap();
        assert!(!store.exists(&address).unwrap());
    }

    #[test]
    fn test_create_test_app() {
        let app = TestApp::new();
        assert!(app.storage.is_empty());
    }
}
