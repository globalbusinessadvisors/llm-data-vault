//! LLM-Memory-Graph adapter for consuming lineage metadata.
//!
//! This adapter provides runtime consumption of lineage metadata from the
//! LLM-Memory-Graph service for:
//! - Lineage relationship tracking
//! - Graph-based artifact relationships
//! - Data provenance tracking
//!
//! # Usage
//!
//! ```ignore
//! use vault_integration::adapters::MemoryGraphAdapter;
//!
//! let adapter = MemoryGraphAdapter::new(config);
//! adapter.initialize().await?;
//!
//! // Attach a lineage relationship
//! adapter.attach_relationship(relationship).await?;
//! ```

use super::{AdapterConfig, AdapterHealth, EcosystemAdapter};
use crate::{IntegrationError, IntegrationResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, info, warn};
use chrono::{DateTime, Utc};

/// Lineage node representing an artifact in the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageNode {
    /// Node ID.
    pub id: String,
    /// Node type.
    pub node_type: NodeType,
    /// Node name.
    pub name: String,
    /// External reference ID (e.g., dataset_id, record_id).
    pub external_id: String,
    /// Node metadata.
    pub metadata: HashMap<String, serde_json::Value>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last updated timestamp.
    pub updated_at: DateTime<Utc>,
    /// Node version.
    pub version: u32,
}

impl LineageNode {
    /// Creates a new lineage node.
    pub fn new(node_type: NodeType, name: impl Into<String>, external_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            node_type,
            name: name.into(),
            external_id: external_id.into(),
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
            version: 1,
        }
    }

    /// Adds metadata to the node.
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Node types in the lineage graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// Dataset node.
    Dataset,
    /// Record node.
    Record,
    /// Version node.
    Version,
    /// Schema node.
    Schema,
    /// Transformation node.
    Transformation,
    /// User/Actor node.
    Actor,
    /// External system node.
    ExternalSystem,
}

/// Lineage relationship between nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageRelationship {
    /// Relationship ID.
    pub id: String,
    /// Source node ID.
    pub source_id: String,
    /// Target node ID.
    pub target_id: String,
    /// Relationship type.
    pub relationship_type: RelationshipType,
    /// Relationship metadata.
    pub metadata: HashMap<String, serde_json::Value>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Relationship weight (for graph algorithms).
    pub weight: Option<f64>,
}

impl LineageRelationship {
    /// Creates a new lineage relationship.
    pub fn new(
        source_id: impl Into<String>,
        target_id: impl Into<String>,
        relationship_type: RelationshipType,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_id: source_id.into(),
            target_id: target_id.into(),
            relationship_type,
            metadata: HashMap::new(),
            created_at: Utc::now(),
            weight: None,
        }
    }

    /// Adds metadata to the relationship.
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Sets the relationship weight.
    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = Some(weight);
        self
    }
}

/// Relationship types in the lineage graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationshipType {
    /// Derived from relationship.
    DerivedFrom,
    /// Contains relationship.
    Contains,
    /// Depends on relationship.
    DependsOn,
    /// Transformed by relationship.
    TransformedBy,
    /// Created by relationship.
    CreatedBy,
    /// Modified by relationship.
    ModifiedBy,
    /// Version of relationship.
    VersionOf,
    /// Validated by relationship.
    ValidatedBy,
    /// Encrypted with relationship.
    EncryptedWith,
    /// Anonymized by relationship.
    AnonymizedBy,
}

/// Lineage query for traversing the graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageQuery {
    /// Starting node ID.
    pub start_node_id: String,
    /// Query direction.
    pub direction: QueryDirection,
    /// Maximum traversal depth.
    pub max_depth: u32,
    /// Filter by relationship types.
    pub relationship_types: Option<Vec<RelationshipType>>,
    /// Filter by node types.
    pub node_types: Option<Vec<NodeType>>,
    /// Include node metadata.
    pub include_metadata: bool,
}

impl LineageQuery {
    /// Creates a new lineage query.
    pub fn new(start_node_id: impl Into<String>) -> Self {
        Self {
            start_node_id: start_node_id.into(),
            direction: QueryDirection::Both,
            max_depth: 10,
            relationship_types: None,
            node_types: None,
            include_metadata: true,
        }
    }

    /// Sets the query direction.
    pub fn with_direction(mut self, direction: QueryDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Sets the maximum depth.
    pub fn with_max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Filters by relationship types.
    pub fn with_relationship_types(mut self, types: Vec<RelationshipType>) -> Self {
        self.relationship_types = Some(types);
        self
    }

    /// Filters by node types.
    pub fn with_node_types(mut self, types: Vec<NodeType>) -> Self {
        self.node_types = Some(types);
        self
    }
}

/// Query direction for graph traversal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryDirection {
    /// Traverse upstream (ancestors).
    Upstream,
    /// Traverse downstream (descendants).
    Downstream,
    /// Traverse both directions.
    Both,
}

/// Lineage query result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageQueryResult {
    /// Query that produced this result.
    pub query: LineageQuery,
    /// Nodes in the result.
    pub nodes: Vec<LineageNode>,
    /// Relationships in the result.
    pub relationships: Vec<LineageRelationship>,
    /// Total nodes traversed.
    pub total_nodes: usize,
    /// Maximum depth reached.
    pub max_depth_reached: u32,
    /// Query execution time in milliseconds.
    pub execution_time_ms: u64,
}

/// LLM-Memory-Graph adapter for consuming lineage metadata.
pub struct MemoryGraphAdapter {
    /// Adapter configuration.
    config: AdapterConfig,
    /// Local node cache.
    node_cache: Arc<RwLock<HashMap<String, LineageNode>>>,
    /// Local relationship cache.
    relationship_cache: Arc<RwLock<Vec<LineageRelationship>>>,
    /// Pending operations buffer.
    pending_ops: Arc<RwLock<Vec<GraphOperation>>>,
    /// Initialization state.
    initialized: Arc<RwLock<bool>>,
}

/// Graph operation for batching.
#[derive(Debug, Clone)]
enum GraphOperation {
    AddNode(LineageNode),
    AddRelationship(LineageRelationship),
    UpdateNode(String, HashMap<String, serde_json::Value>),
    DeleteNode(String),
    DeleteRelationship(String),
}

impl MemoryGraphAdapter {
    /// Creates a new Memory Graph adapter.
    pub fn new(config: AdapterConfig) -> Self {
        Self {
            config,
            node_cache: Arc::new(RwLock::new(HashMap::new())),
            relationship_cache: Arc::new(RwLock::new(Vec::new())),
            pending_ops: Arc::new(RwLock::new(Vec::new())),
            initialized: Arc::new(RwLock::new(false)),
        }
    }

    /// Creates an adapter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AdapterConfig::default())
    }

    /// Registers a lineage node in the graph.
    pub async fn register_node(&self, node: LineageNode) -> IntegrationResult<String> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Memory Graph adapter is disabled".into()));
        }

        debug!(
            node_id = %node.id,
            node_type = ?node.node_type,
            "Registering lineage node in LLM-Memory-Graph"
        );

        let node_id = node.id.clone();
        self.node_cache.write().insert(node_id.clone(), node.clone());
        self.pending_ops.write().push(GraphOperation::AddNode(node));

        Ok(node_id)
    }

    /// Attaches a lineage relationship between nodes.
    pub async fn attach_relationship(&self, relationship: LineageRelationship) -> IntegrationResult<String> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Memory Graph adapter is disabled".into()));
        }

        debug!(
            relationship_id = %relationship.id,
            source = %relationship.source_id,
            target = %relationship.target_id,
            relationship_type = ?relationship.relationship_type,
            "Attaching lineage relationship in LLM-Memory-Graph"
        );

        let rel_id = relationship.id.clone();
        self.relationship_cache.write().push(relationship.clone());
        self.pending_ops.write().push(GraphOperation::AddRelationship(relationship));

        Ok(rel_id)
    }

    /// Queries the lineage graph.
    pub async fn query_lineage(&self, query: LineageQuery) -> IntegrationResult<LineageQueryResult> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Memory Graph adapter is disabled".into()));
        }

        let start = std::time::Instant::now();

        debug!(
            start_node = %query.start_node_id,
            direction = ?query.direction,
            max_depth = query.max_depth,
            "Querying lineage from LLM-Memory-Graph"
        );

        // Get cached nodes and relationships
        let nodes: Vec<LineageNode> = self.node_cache.read().values().cloned().collect();
        let relationships: Vec<LineageRelationship> = self.relationship_cache.read().clone();

        let execution_time = start.elapsed().as_millis() as u64;

        Ok(LineageQueryResult {
            query,
            nodes,
            relationships,
            total_nodes: self.node_cache.read().len(),
            max_depth_reached: 0,
            execution_time_ms: execution_time,
        })
    }

    /// Gets a node by ID.
    pub async fn get_node(&self, node_id: &str) -> IntegrationResult<Option<LineageNode>> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Memory Graph adapter is disabled".into()));
        }

        debug!(node_id = %node_id, "Getting lineage node from LLM-Memory-Graph");

        Ok(self.node_cache.read().get(node_id).cloned())
    }

    /// Gets relationships for a node.
    pub async fn get_relationships(&self, node_id: &str) -> IntegrationResult<Vec<LineageRelationship>> {
        if !self.config.enabled {
            return Err(IntegrationError::Internal("Memory Graph adapter is disabled".into()));
        }

        debug!(node_id = %node_id, "Getting relationships from LLM-Memory-Graph");

        let relationships: Vec<LineageRelationship> = self.relationship_cache
            .read()
            .iter()
            .filter(|r| r.source_id == node_id || r.target_id == node_id)
            .cloned()
            .collect();

        Ok(relationships)
    }

    /// Creates a derived-from relationship.
    pub async fn mark_derived_from(
        &self,
        source_id: impl Into<String>,
        target_id: impl Into<String>,
    ) -> IntegrationResult<String> {
        let relationship = LineageRelationship::new(source_id, target_id, RelationshipType::DerivedFrom);
        self.attach_relationship(relationship).await
    }

    /// Creates a version-of relationship.
    pub async fn mark_version_of(
        &self,
        source_id: impl Into<String>,
        target_id: impl Into<String>,
    ) -> IntegrationResult<String> {
        let relationship = LineageRelationship::new(source_id, target_id, RelationshipType::VersionOf);
        self.attach_relationship(relationship).await
    }

    /// Creates a transformed-by relationship.
    pub async fn mark_transformed_by(
        &self,
        source_id: impl Into<String>,
        transformation_id: impl Into<String>,
    ) -> IntegrationResult<String> {
        let relationship = LineageRelationship::new(source_id, transformation_id, RelationshipType::TransformedBy);
        self.attach_relationship(relationship).await
    }

    /// Flushes pending operations to the graph.
    pub async fn flush(&self) -> IntegrationResult<usize> {
        let ops: Vec<GraphOperation> = self.pending_ops.write().drain(..).collect();
        let count = ops.len();

        if count > 0 {
            debug!(count = count, "Flushing graph operations to LLM-Memory-Graph");
            // In production, this would send to the Memory Graph service
        }

        Ok(count)
    }

    /// Returns graph statistics.
    pub fn graph_stats(&self) -> GraphStats {
        GraphStats {
            node_count: self.node_cache.read().len(),
            relationship_count: self.relationship_cache.read().len(),
            pending_operations: self.pending_ops.read().len(),
        }
    }

    /// Clears all caches.
    pub fn clear_caches(&self) {
        self.node_cache.write().clear();
        self.relationship_cache.write().clear();
        info!("Memory Graph caches cleared");
    }
}

/// Graph statistics.
#[derive(Debug, Clone)]
pub struct GraphStats {
    /// Number of cached nodes.
    pub node_count: usize,
    /// Number of cached relationships.
    pub relationship_count: usize,
    /// Number of pending operations.
    pub pending_operations: usize,
}

#[async_trait]
impl EcosystemAdapter for MemoryGraphAdapter {
    fn name(&self) -> &str {
        "llm-memory-graph"
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

        Ok(AdapterHealth::healthy("Memory Graph adapter is healthy"))
    }

    async fn initialize(&self) -> IntegrationResult<()> {
        if *self.initialized.read() {
            warn!("Memory Graph adapter already initialized");
            return Ok(());
        }

        info!(
            base_url = ?self.config.base_url,
            "Initializing LLM-Memory-Graph adapter"
        );

        *self.initialized.write() = true;

        info!("LLM-Memory-Graph adapter initialized successfully");
        Ok(())
    }

    async fn shutdown(&self) -> IntegrationResult<()> {
        info!("Shutting down LLM-Memory-Graph adapter");

        // Flush pending operations
        self.flush().await?;

        *self.initialized.write() = false;
        self.clear_caches();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_adapter_creation() {
        let adapter = MemoryGraphAdapter::with_defaults();
        assert_eq!(adapter.name(), "llm-memory-graph");
    }

    #[tokio::test]
    async fn test_node_registration() {
        let adapter = MemoryGraphAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let node = LineageNode::new(NodeType::Dataset, "Test Dataset", "ds-123")
            .with_metadata("owner", serde_json::json!("user@example.com"));

        let node_id = adapter.register_node(node).await.unwrap();
        assert!(!node_id.is_empty());

        let stats = adapter.graph_stats();
        assert_eq!(stats.node_count, 1);
        assert_eq!(stats.pending_operations, 1);
    }

    #[tokio::test]
    async fn test_relationship_attachment() {
        let adapter = MemoryGraphAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        let relationship = LineageRelationship::new("node-1", "node-2", RelationshipType::DerivedFrom)
            .with_metadata("reason", serde_json::json!("data transformation"));

        let rel_id = adapter.attach_relationship(relationship).await.unwrap();
        assert!(!rel_id.is_empty());

        let stats = adapter.graph_stats();
        assert_eq!(stats.relationship_count, 1);
    }

    #[tokio::test]
    async fn test_lineage_query() {
        let adapter = MemoryGraphAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        // Register nodes
        let node1 = LineageNode::new(NodeType::Dataset, "Source", "ds-source");
        let node2 = LineageNode::new(NodeType::Dataset, "Target", "ds-target");

        adapter.register_node(node1).await.unwrap();
        adapter.register_node(node2).await.unwrap();

        // Create relationship
        adapter.mark_derived_from("ds-target", "ds-source").await.unwrap();

        // Query lineage
        let query = LineageQuery::new("ds-source")
            .with_direction(QueryDirection::Downstream)
            .with_max_depth(5);

        let result = adapter.query_lineage(query).await.unwrap();
        assert_eq!(result.nodes.len(), 2);
        assert_eq!(result.relationships.len(), 1);
    }

    #[tokio::test]
    async fn test_convenience_methods() {
        let adapter = MemoryGraphAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        adapter.mark_derived_from("node-a", "node-b").await.unwrap();
        adapter.mark_version_of("node-c", "node-a").await.unwrap();
        adapter.mark_transformed_by("node-d", "transform-1").await.unwrap();

        let stats = adapter.graph_stats();
        assert_eq!(stats.relationship_count, 3);
    }

    #[tokio::test]
    async fn test_flush_operations() {
        let adapter = MemoryGraphAdapter::with_defaults();
        adapter.initialize().await.unwrap();

        adapter.register_node(LineageNode::new(NodeType::Dataset, "Test", "test-1")).await.unwrap();
        adapter.mark_derived_from("a", "b").await.unwrap();

        let count = adapter.flush().await.unwrap();
        assert_eq!(count, 2);

        let stats = adapter.graph_stats();
        assert_eq!(stats.pending_operations, 0);
    }
}
