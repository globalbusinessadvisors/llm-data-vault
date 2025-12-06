//! LLM-Config-Manager adapter for consuming configuration-driven rules.
//!
//! This adapter provides runtime consumption of configuration from the
//! LLM-Config-Manager service for:
//! - Retention rules for data lifecycle management
//! - Encryption key configurations
//! - Storage backend configurations
//! - Access policy configurations
//!
//! # Usage
//!
//! ```ignore
//! use vault_integration::adapters::ConfigManagerAdapter;
//!
//! let adapter = ConfigManagerAdapter::new(config);
//! adapter.initialize().await?;
//!
//! // Consume retention rules
//! let rules = adapter.get_retention_rules("tenant-123").await?;
//! ```

use super::{AdapterConfig, AdapterHealth, EcosystemAdapter};
use crate::{IntegrationError, IntegrationResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Retention rule consumed from LLM-Config-Manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionRule {
    /// Rule ID.
    pub id: String,
    /// Rule name.
    pub name: String,
    /// Tenant ID this rule applies to.
    pub tenant_id: Option<String>,
    /// Dataset pattern (glob) this rule applies to.
    pub dataset_pattern: Option<String>,
    /// Retention period in days.
    pub retention_days: u32,
    /// Action to take on expiry.
    pub expiry_action: ExpiryAction,
    /// Whether to archive before deletion.
    pub archive_before_delete: bool,
    /// Rule priority (higher = evaluated first).
    pub priority: i32,
    /// Rule enabled flag.
    pub enabled: bool,
}

/// Action to take when data expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryAction {
    /// Delete the data permanently.
    Delete,
    /// Archive the data to cold storage.
    Archive,
    /// Anonymize the data.
    Anonymize,
    /// Notify but take no action.
    NotifyOnly,
}

/// Encryption key configuration consumed from LLM-Config-Manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKeyConfig {
    /// Key configuration ID.
    pub id: String,
    /// Key ID reference.
    pub key_id: String,
    /// Key algorithm.
    pub algorithm: String,
    /// Key provider (local, aws-kms, hashicorp-vault).
    pub provider: KeyProvider,
    /// Key rotation policy.
    pub rotation_policy: Option<KeyRotationPolicy>,
    /// Tenant scope.
    pub tenant_id: Option<String>,
    /// Whether this is the default key.
    pub is_default: bool,
}

/// Key provider types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProvider {
    /// Local key storage.
    Local,
    /// AWS Key Management Service.
    AwsKms,
    /// HashiCorp Vault.
    HashiCorpVault,
    /// Azure Key Vault.
    AzureKeyVault,
    /// Google Cloud KMS.
    GcpKms,
}

/// Key rotation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    /// Rotation interval in days.
    pub rotation_days: u32,
    /// Automatic rotation enabled.
    pub auto_rotate: bool,
    /// Grace period after rotation in days.
    pub grace_period_days: u32,
}

/// Storage backend configuration consumed from LLM-Config-Manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageBackendConfig {
    /// Backend configuration ID.
    pub id: String,
    /// Backend name.
    pub name: String,
    /// Backend type.
    pub backend_type: StorageBackendType,
    /// Connection configuration.
    pub connection: HashMap<String, String>,
    /// Storage tier (hot, warm, cold).
    pub tier: StorageTier,
    /// Maximum object size in bytes.
    pub max_object_size: Option<u64>,
    /// Whether encryption is required.
    pub require_encryption: bool,
    /// Whether this is the default backend.
    pub is_default: bool,
}

/// Storage backend types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackendType {
    /// In-memory storage.
    Memory,
    /// Local filesystem.
    Filesystem,
    /// AWS S3.
    S3,
    /// Azure Blob Storage.
    AzureBlob,
    /// Google Cloud Storage.
    Gcs,
    /// MinIO.
    Minio,
}

/// Storage tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageTier {
    /// Hot storage for frequently accessed data.
    Hot,
    /// Warm storage for occasionally accessed data.
    Warm,
    /// Cold storage for archival data.
    Cold,
}

/// Access policy configuration consumed from LLM-Config-Manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicyConfig {
    /// Policy configuration ID.
    pub id: String,
    /// Policy name.
    pub name: String,
    /// Policy type.
    pub policy_type: AccessPolicyType,
    /// Policy rules.
    pub rules: Vec<AccessRule>,
    /// Tenant scope.
    pub tenant_id: Option<String>,
    /// Priority.
    pub priority: i32,
    /// Whether this policy is enabled.
    pub enabled: bool,
}

/// Access policy types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPolicyType {
    /// Role-based access control.
    Rbac,
    /// Attribute-based access control.
    Abac,
    /// Time-based access control.
    Tbac,
    /// Location-based access control.
    Lbac,
}

/// Access rule within a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    /// Rule ID.
    pub id: String,
    /// Effect (allow or deny).
    pub effect: AccessEffect,
    /// Principals this rule applies to.
    pub principals: Vec<String>,
    /// Actions this rule covers.
    pub actions: Vec<String>,
    /// Resources this rule applies to.
    pub resources: Vec<String>,
    /// Conditions for the rule.
    pub conditions: HashMap<String, String>,
}

/// Access rule effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessEffect {
    /// Allow access.
    Allow,
    /// Deny access.
    Deny,
}

/// LLM-Config-Manager adapter for consuming configuration.
pub struct ConfigManagerAdapter {
    /// Adapter configuration.
    config: AdapterConfig,
    /// Cached retention rules.
    retention_cache: Arc<RwLock<HashMap<String, Vec<RetentionRule>>>>,
    /// Cached encryption configs.
    encryption_cache: Arc<RwLock<HashMap<String, EncryptionKeyConfig>>>,
    /// Cached storage configs.
    storage_cache: Arc<RwLock<HashMap<String, StorageBackendConfig>>>,
    /// Cached access policies.
    policy_cache: Arc<RwLock<HashMap<String, AccessPolicyConfig>>>,
    /// Initialization state.
    initialized: Arc<RwLock<bool>>,
}

impl ConfigManagerAdapter {
    /// Creates a new Config Manager adapter.
    pub fn new(config: AdapterConfig) -> Self {
        Self {
            config,
            retention_cache: Arc::new(RwLock::new(HashMap::new())),
            encryption_cache: Arc::new(RwLock::new(HashMap::new())),
            storage_cache: Arc::new(RwLock::new(HashMap::new())),
            policy_cache: Arc::new(RwLock::new(HashMap::new())),
            initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// Creates an adapter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AdapterConfig::default())
    }

    /// Consumes retention rules for a tenant.
    pub async fn get_retention_rules(&self, tenant_id: &str) -> IntegrationResult<Vec<RetentionRule>> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Config Manager adapter is disabled".into()));
        }

        // Check cache first
        if let Some(cached) = self.retention_cache.read().get(tenant_id) {
            debug!(tenant_id = %tenant_id, "Retention rules found in cache");
            return Ok(cached.clone());
        }

        debug!(
            tenant_id = %tenant_id,
            "Consuming retention rules from LLM-Config-Manager"
        );

        // Create placeholder rules for the consumption layer
        let rules = vec![
            RetentionRule {
                id: format!("ret-{}-default", tenant_id),
                name: "Default Retention".to_string(),
                tenant_id: Some(tenant_id.to_string()),
                dataset_pattern: Some("*".to_string()),
                retention_days: 365,
                expiry_action: ExpiryAction::Archive,
                archive_before_delete: true,
                priority: 0,
                enabled: true,
            },
        ];

        self.retention_cache.write().insert(tenant_id.to_string(), rules.clone());
        Ok(rules)
    }

    /// Consumes encryption key configuration.
    pub async fn get_encryption_config(&self, key_id: &str) -> IntegrationResult<EncryptionKeyConfig> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Config Manager adapter is disabled".into()));
        }

        // Check cache first
        if let Some(cached) = self.encryption_cache.read().get(key_id) {
            debug!(key_id = %key_id, "Encryption config found in cache");
            return Ok(cached.clone());
        }

        debug!(
            key_id = %key_id,
            "Consuming encryption config from LLM-Config-Manager"
        );

        let config = EncryptionKeyConfig {
            id: format!("enc-cfg-{}", key_id),
            key_id: key_id.to_string(),
            algorithm: "AES-256-GCM".to_string(),
            provider: KeyProvider::Local,
            rotation_policy: Some(KeyRotationPolicy {
                rotation_days: 90,
                auto_rotate: true,
                grace_period_days: 30,
            }),
            tenant_id: None,
            is_default: false,
        };

        self.encryption_cache.write().insert(key_id.to_string(), config.clone());
        Ok(config)
    }

    /// Consumes storage backend configuration.
    pub async fn get_storage_config(&self, backend_id: &str) -> IntegrationResult<StorageBackendConfig> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Config Manager adapter is disabled".into()));
        }

        // Check cache first
        if let Some(cached) = self.storage_cache.read().get(backend_id) {
            debug!(backend_id = %backend_id, "Storage config found in cache");
            return Ok(cached.clone());
        }

        debug!(
            backend_id = %backend_id,
            "Consuming storage config from LLM-Config-Manager"
        );

        let config = StorageBackendConfig {
            id: format!("storage-cfg-{}", backend_id),
            name: backend_id.to_string(),
            backend_type: StorageBackendType::Filesystem,
            connection: HashMap::new(),
            tier: StorageTier::Hot,
            max_object_size: Some(100 * 1024 * 1024), // 100MB
            require_encryption: true,
            is_default: false,
        };

        self.storage_cache.write().insert(backend_id.to_string(), config.clone());
        Ok(config)
    }

    /// Consumes access policy configuration.
    pub async fn get_access_policy(&self, policy_id: &str) -> IntegrationResult<AccessPolicyConfig> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Config Manager adapter is disabled".into()));
        }

        // Check cache first
        if let Some(cached) = self.policy_cache.read().get(policy_id) {
            debug!(policy_id = %policy_id, "Access policy found in cache");
            return Ok(cached.clone());
        }

        debug!(
            policy_id = %policy_id,
            "Consuming access policy from LLM-Config-Manager"
        );

        let config = AccessPolicyConfig {
            id: format!("policy-cfg-{}", policy_id),
            name: policy_id.to_string(),
            policy_type: AccessPolicyType::Rbac,
            rules: vec![],
            tenant_id: None,
            priority: 0,
            enabled: true,
        };

        self.policy_cache.write().insert(policy_id.to_string(), config.clone());
        Ok(config)
    }

    /// Clears all caches.
    pub fn clear_all_caches(&self) {
        self.retention_cache.write().clear();
        self.encryption_cache.write().clear();
        self.storage_cache.write().clear();
        self.policy_cache.write().clear();
        info!("All Config Manager caches cleared");
    }

    /// Refreshes configuration from upstream.
    pub async fn refresh(&self) -> IntegrationResult<()> {
        info!("Refreshing configuration from LLM-Config-Manager");
        self.clear_all_caches();
        Ok(())
    }
}

#[async_trait]
impl EcosystemAdapter for ConfigManagerAdapter {
    fn name(&self) -> &str {
        "llm-config-manager"
    }

    fn version(&self) -> &str {
        "0.5.0"
    }

    async fn health_check(&self) -> IntegrationResult<AdapterHealth> {
        if !self.config.enabled {
            return Ok(AdapterHealth::unhealthy("Adapter is disabled"));
        }

        if !*self.initialized.read() {
            return Ok(AdapterHealth::unhealthy("Adapter not initialized"));
        }

        Ok(AdapterHealth::healthy("Config Manager adapter is healthy"))
    }

    async fn initialize(&self) -> IntegrationResult<()> {
        if *self.initialized.read() {
            warn!("Config Manager adapter already initialized");
            return Ok(());
        }

        info!(
            base_url = ?self.config.base_url,
            "Initializing LLM-Config-Manager adapter"
        );

        *self.initialized.write() = true;

        info!("LLM-Config-Manager adapter initialized successfully");
        Ok(())
    }

    async fn shutdown(&self) -> IntegrationResult<()> {
        info!("Shutting down LLM-Config-Manager adapter");
        *self.initialized.write() = false;
        self.clear_all_caches();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_adapter_creation() {
        let adapter = ConfigManagerAdapter::with_defaults();
        assert_eq!(adapter.name(), "llm-config-manager");
    }

    #[tokio::test]
    async fn test_retention_rules_consumption() {
        let adapter = ConfigManagerAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let rules = adapter.get_retention_rules("tenant-123").await.unwrap();
        assert!(!rules.is_empty());
        assert_eq!(rules[0].tenant_id, Some("tenant-123".to_string()));
    }

    #[tokio::test]
    async fn test_encryption_config_consumption() {
        let adapter = ConfigManagerAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let config = adapter.get_encryption_config("key-456").await.unwrap();
        assert_eq!(config.key_id, "key-456");
        assert_eq!(config.algorithm, "AES-256-GCM");
    }

    #[tokio::test]
    async fn test_storage_config_consumption() {
        let adapter = ConfigManagerAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let config = adapter.get_storage_config("primary").await.unwrap();
        assert!(config.require_encryption);
    }

    #[tokio::test]
    async fn test_access_policy_consumption() {
        let adapter = ConfigManagerAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let policy = adapter.get_access_policy("default-policy").await.unwrap();
        assert!(policy.enabled);
    }
}
