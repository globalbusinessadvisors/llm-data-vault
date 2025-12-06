//! LLM-Schema-Registry adapter for consuming canonical schema definitions.
//!
//! This adapter provides runtime consumption of schema definitions from the
//! LLM-Schema-Registry service for:
//! - Dataset schemas
//! - Metadata envelope schemas
//! - Lineage record schemas
//!
//! # Usage
//!
//! ```ignore
//! use vault_integration::adapters::SchemaRegistryAdapter;
//!
//! let adapter = SchemaRegistryAdapter::new(config);
//! adapter.initialize().await?;
//!
//! // Consume schema for a dataset
//! let schema = adapter.get_dataset_schema("my-dataset-v1").await?;
//! ```

use super::{AdapterConfig, AdapterHealth, EcosystemAdapter};
use crate::{IntegrationError, IntegrationResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Schema definition consumed from LLM-Schema-Registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDefinition {
    /// Schema ID.
    pub id: String,
    /// Schema name.
    pub name: String,
    /// Schema version.
    pub version: String,
    /// Schema namespace.
    pub namespace: Option<String>,
    /// Schema type (dataset, metadata, lineage).
    pub schema_type: SchemaType,
    /// Schema format (JSON Schema, Avro, Protobuf).
    pub format: SchemaFormat,
    /// The actual schema content.
    pub content: serde_json::Value,
    /// Schema fingerprint for comparison.
    pub fingerprint: String,
    /// Compatibility mode.
    pub compatibility: CompatibilityMode,
    /// Schema metadata.
    pub metadata: HashMap<String, String>,
}

/// Schema types supported by the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaType {
    /// Dataset record schema.
    Dataset,
    /// Metadata envelope schema.
    MetadataEnvelope,
    /// Lineage record schema.
    LineageRecord,
    /// Custom schema type.
    Custom,
}

/// Schema formats supported by the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaFormat {
    /// JSON Schema.
    JsonSchema,
    /// Apache Avro.
    Avro,
    /// Protocol Buffers.
    Protobuf,
    /// Apache Arrow.
    Arrow,
}

/// Schema compatibility modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityMode {
    /// No compatibility checks.
    None,
    /// New schema can read old data.
    Backward,
    /// Old schema can read new data.
    Forward,
    /// Both backward and forward compatible.
    Full,
}

/// Schema resolution result from the registry.
#[derive(Debug, Clone)]
pub struct SchemaResolution {
    /// The resolved schema.
    pub schema: SchemaDefinition,
    /// Whether this was from cache.
    pub from_cache: bool,
    /// Resolution timestamp.
    pub resolved_at: chrono::DateTime<chrono::Utc>,
}

/// LLM-Schema-Registry adapter for consuming schema definitions.
pub struct SchemaRegistryAdapter {
    /// Adapter configuration.
    config: AdapterConfig,
    /// Schema cache.
    cache: Arc<RwLock<HashMap<String, SchemaDefinition>>>,
    /// Initialization state.
    initialized: Arc<RwLock<bool>>,
}

impl SchemaRegistryAdapter {
    /// Creates a new Schema Registry adapter.
    pub fn new(config: AdapterConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// Creates an adapter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AdapterConfig::default())
    }

    /// Consumes a dataset schema definition by ID.
    pub async fn get_dataset_schema(&self, schema_id: &str) -> IntegrationResult<SchemaResolution> {
        self.get_schema(schema_id, SchemaType::Dataset).await
    }

    /// Consumes a metadata envelope schema definition by ID.
    pub async fn get_metadata_schema(&self, schema_id: &str) -> IntegrationResult<SchemaResolution> {
        self.get_schema(schema_id, SchemaType::MetadataEnvelope).await
    }

    /// Consumes a lineage record schema definition by ID.
    pub async fn get_lineage_schema(&self, schema_id: &str) -> IntegrationResult<SchemaResolution> {
        self.get_schema(schema_id, SchemaType::LineageRecord).await
    }

    /// Consumes a schema definition by ID and type.
    async fn get_schema(&self, schema_id: &str, schema_type: SchemaType) -> IntegrationResult<SchemaResolution> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Schema Registry adapter is disabled".into()));
        }

        // Check cache first
        if let Some(cached) = self.cache.read().get(schema_id) {
            debug!(schema_id = %schema_id, "Schema found in cache");
            return Ok(SchemaResolution {
                schema: cached.clone(),
                from_cache: true,
                resolved_at: chrono::Utc::now(),
            });
        }

        // In production, this would fetch from the Schema Registry service.
        // For Phase 2B, we return a placeholder indicating the consumption point.
        debug!(
            schema_id = %schema_id,
            schema_type = ?schema_type,
            "Consuming schema from LLM-Schema-Registry"
        );

        // Create placeholder schema for the consumption layer
        let schema = SchemaDefinition {
            id: schema_id.to_string(),
            name: format!("{}-schema", schema_id),
            version: "1.0.0".to_string(),
            namespace: Some("llm.data-vault".to_string()),
            schema_type,
            format: SchemaFormat::JsonSchema,
            content: serde_json::json!({
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "properties": {},
                "additionalProperties": true
            }),
            fingerprint: format!("fp-{}", schema_id),
            compatibility: CompatibilityMode::Backward,
            metadata: HashMap::new(),
        };

        // Cache the schema
        self.cache.write().insert(schema_id.to_string(), schema.clone());

        Ok(SchemaResolution {
            schema,
            from_cache: false,
            resolved_at: chrono::Utc::now(),
        })
    }

    /// Lists all cached schemas.
    pub fn list_cached_schemas(&self) -> Vec<String> {
        self.cache.read().keys().cloned().collect()
    }

    /// Clears the schema cache.
    pub fn clear_cache(&self) {
        self.cache.write().clear();
        info!("Schema cache cleared");
    }

    /// Invalidates a specific schema in the cache.
    pub fn invalidate(&self, schema_id: &str) -> bool {
        self.cache.write().remove(schema_id).is_some()
    }

    /// Validates data against a consumed schema.
    pub async fn validate_against_schema(
        &self,
        schema_id: &str,
        data: &serde_json::Value,
    ) -> IntegrationResult<ValidationResult> {
        let resolution = self.get_schema(schema_id, SchemaType::Dataset).await?;

        // In production, this would perform actual JSON Schema validation.
        // For Phase 2B, we indicate the validation consumption point.
        debug!(
            schema_id = %schema_id,
            "Validating data against consumed schema"
        );

        Ok(ValidationResult {
            valid: true,
            schema_id: schema_id.to_string(),
            errors: vec![],
        })
    }
}

/// Schema validation result.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether the data is valid.
    pub valid: bool,
    /// Schema ID used for validation.
    pub schema_id: String,
    /// Validation errors (if any).
    pub errors: Vec<String>,
}

#[async_trait]
impl EcosystemAdapter for SchemaRegistryAdapter {
    fn name(&self) -> &str {
        "llm-schema-registry"
    }

    fn version(&self) -> &str {
        "0.1.0"
    }

    async fn health_check(&self) -> IntegrationResult<AdapterHealth> {
        if !self.config.enabled {
            return Ok(AdapterHealth::unhealthy("Adapter is disabled"));
        }

        if !*self.initialized.read() {
            return Ok(AdapterHealth::unhealthy("Adapter not initialized"));
        }

        // In production, this would ping the Schema Registry service.
        Ok(AdapterHealth::healthy("Schema Registry adapter is healthy"))
    }

    async fn initialize(&self) -> IntegrationResult<()> {
        if *self.initialized.read() {
            warn!("Schema Registry adapter already initialized");
            return Ok(());
        }

        info!(
            base_url = ?self.config.base_url,
            "Initializing LLM-Schema-Registry adapter"
        );

        // In production, this would establish connection to the Schema Registry.
        *self.initialized.write() = true;

        info!("LLM-Schema-Registry adapter initialized successfully");
        Ok(())
    }

    async fn shutdown(&self) -> IntegrationResult<()> {
        info!("Shutting down LLM-Schema-Registry adapter");
        *self.initialized.write() = false;
        self.clear_cache();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_adapter_creation() {
        let adapter = SchemaRegistryAdapter::with_defaults();
        assert_eq!(adapter.name(), "llm-schema-registry");
    }

    #[tokio::test]
    async fn test_adapter_initialization() {
        let adapter = SchemaRegistryAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let health = adapter.health_check().await.unwrap();
        assert!(health.healthy);
    }

    #[tokio::test]
    async fn test_schema_consumption() {
        let adapter = SchemaRegistryAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let resolution = adapter.get_dataset_schema("test-schema").await.unwrap();
        assert_eq!(resolution.schema.id, "test-schema");
        assert!(!resolution.from_cache);

        // Second call should be from cache
        let cached = adapter.get_dataset_schema("test-schema").await.unwrap();
        assert!(cached.from_cache);
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let adapter = SchemaRegistryAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        adapter.get_dataset_schema("schema-1").await.unwrap();
        adapter.get_metadata_schema("schema-2").await.unwrap();

        assert_eq!(adapter.list_cached_schemas().len(), 2);

        adapter.invalidate("schema-1");
        assert_eq!(adapter.list_cached_schemas().len(), 1);

        adapter.clear_cache();
        assert_eq!(adapter.list_cached_schemas().len(), 0);
    }
}
