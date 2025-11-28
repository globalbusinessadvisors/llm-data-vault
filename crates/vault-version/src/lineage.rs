//! Data lineage tracking.

use crate::{CommitId, VersionError, VersionResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Lineage type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineageType {
    /// Direct derivation (copy, transformation).
    Derived,
    /// Aggregation from multiple sources.
    Aggregated,
    /// Filtered subset.
    Filtered,
    /// Joined from multiple sources.
    Joined,
    /// External import.
    Imported,
    /// Model training data.
    Training,
    /// Model inference input.
    Inference,
    /// Manual entry.
    Manual,
    /// System generated.
    System,
}

/// A lineage node representing a data asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageNode {
    /// Unique node ID.
    pub id: String,
    /// Node name/label.
    pub name: String,
    /// Node type (dataset, model, pipeline, etc.).
    pub node_type: NodeType,
    /// Associated commit (if versioned).
    pub commit: Option<CommitId>,
    /// Dataset ID (if applicable).
    pub dataset_id: Option<String>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last modified timestamp.
    pub modified_at: DateTime<Utc>,
    /// Node metadata.
    pub metadata: HashMap<String, String>,
    /// Tags.
    pub tags: HashSet<String>,
}

/// Node type in lineage graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// Raw data source.
    Source,
    /// Dataset.
    Dataset,
    /// Transformation pipeline.
    Pipeline,
    /// ML Model.
    Model,
    /// External system.
    External,
    /// Output/export.
    Output,
    /// Intermediate result.
    Intermediate,
}

impl LineageNode {
    /// Creates a new lineage node.
    pub fn new(id: impl Into<String>, name: impl Into<String>, node_type: NodeType) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            name: name.into(),
            node_type,
            commit: None,
            dataset_id: None,
            created_at: now,
            modified_at: now,
            metadata: HashMap::new(),
            tags: HashSet::new(),
        }
    }

    /// Creates a dataset node.
    pub fn dataset(id: impl Into<String>, name: impl Into<String>, dataset_id: impl Into<String>) -> Self {
        let mut node = Self::new(id, name, NodeType::Dataset);
        node.dataset_id = Some(dataset_id.into());
        node
    }

    /// Creates a source node.
    pub fn source(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id, name, NodeType::Source)
    }

    /// Creates a model node.
    pub fn model(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(id, name, NodeType::Model)
    }

    /// Sets the commit.
    #[must_use]
    pub fn with_commit(mut self, commit: CommitId) -> Self {
        self.commit = Some(commit);
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Adds a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.insert(tag.into());
        self
    }
}

/// A lineage edge representing a relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEdge {
    /// Source node ID.
    pub source: String,
    /// Target node ID.
    pub target: String,
    /// Lineage type.
    pub lineage_type: LineageType,
    /// Transformation description.
    pub transformation: Option<String>,
    /// Timestamp when relationship was established.
    pub timestamp: DateTime<Utc>,
    /// Edge metadata.
    pub metadata: HashMap<String, String>,
}

impl LineageEdge {
    /// Creates a new lineage edge.
    pub fn new(
        source: impl Into<String>,
        target: impl Into<String>,
        lineage_type: LineageType,
    ) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            lineage_type,
            transformation: None,
            timestamp: Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Sets the transformation description.
    #[must_use]
    pub fn with_transformation(mut self, desc: impl Into<String>) -> Self {
        self.transformation = Some(desc.into());
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Lineage graph for tracking data provenance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Lineage {
    /// Nodes by ID.
    nodes: HashMap<String, LineageNode>,
    /// Edges (adjacency list by source).
    edges_by_source: HashMap<String, Vec<LineageEdge>>,
    /// Reverse edges (adjacency list by target).
    edges_by_target: HashMap<String, Vec<LineageEdge>>,
}

impl Lineage {
    /// Creates an empty lineage graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a node to the graph.
    pub fn add_node(&mut self, node: LineageNode) -> VersionResult<()> {
        if self.nodes.contains_key(&node.id) {
            return Err(VersionError::LineageError(format!(
                "Node '{}' already exists",
                node.id
            )));
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    /// Gets a node by ID.
    pub fn get_node(&self, id: &str) -> Option<&LineageNode> {
        self.nodes.get(id)
    }

    /// Gets a mutable node by ID.
    pub fn get_node_mut(&mut self, id: &str) -> Option<&mut LineageNode> {
        self.nodes.get_mut(id)
    }

    /// Removes a node and its edges.
    pub fn remove_node(&mut self, id: &str) -> Option<LineageNode> {
        let node = self.nodes.remove(id)?;

        // Remove edges where this node is source
        self.edges_by_source.remove(id);

        // Remove edges where this node is target
        self.edges_by_target.remove(id);

        // Remove references from other adjacency lists
        for edges in self.edges_by_source.values_mut() {
            edges.retain(|e| e.target != id);
        }
        for edges in self.edges_by_target.values_mut() {
            edges.retain(|e| e.source != id);
        }

        Some(node)
    }

    /// Adds an edge to the graph.
    pub fn add_edge(&mut self, edge: LineageEdge) -> VersionResult<()> {
        // Validate nodes exist
        if !self.nodes.contains_key(&edge.source) {
            return Err(VersionError::LineageError(format!(
                "Source node '{}' not found",
                edge.source
            )));
        }
        if !self.nodes.contains_key(&edge.target) {
            return Err(VersionError::LineageError(format!(
                "Target node '{}' not found",
                edge.target
            )));
        }

        // Check for cycles if this would create one
        if self.would_create_cycle(&edge.source, &edge.target) {
            return Err(VersionError::LineageError(
                "Adding edge would create a cycle".to_string(),
            ));
        }

        // Add to adjacency lists
        self.edges_by_source
            .entry(edge.source.clone())
            .or_default()
            .push(edge.clone());

        self.edges_by_target
            .entry(edge.target.clone())
            .or_default()
            .push(edge);

        Ok(())
    }

    /// Checks if adding an edge would create a cycle.
    fn would_create_cycle(&self, source: &str, target: &str) -> bool {
        // If target can reach source, adding source->target would create a cycle
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(target);

        while let Some(node) = queue.pop_front() {
            if node == source {
                return true;
            }
            if visited.insert(node.to_string()) {
                if let Some(edges) = self.edges_by_source.get(node) {
                    for edge in edges {
                        queue.push_back(&edge.target);
                    }
                }
            }
        }

        false
    }

    /// Gets upstream nodes (ancestors).
    pub fn upstream(&self, node_id: &str) -> Vec<&LineageNode> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(node_id.to_string());

        while let Some(current) = queue.pop_front() {
            if let Some(edges) = self.edges_by_target.get(&current) {
                for edge in edges {
                    if visited.insert(edge.source.clone()) {
                        if let Some(node) = self.nodes.get(&edge.source) {
                            result.push(node);
                        }
                        queue.push_back(edge.source.clone());
                    }
                }
            }
        }

        result
    }

    /// Gets downstream nodes (descendants).
    pub fn downstream(&self, node_id: &str) -> Vec<&LineageNode> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(node_id.to_string());

        while let Some(current) = queue.pop_front() {
            if let Some(edges) = self.edges_by_source.get(&current) {
                for edge in edges {
                    if visited.insert(edge.target.clone()) {
                        if let Some(node) = self.nodes.get(&edge.target) {
                            result.push(node);
                        }
                        queue.push_back(edge.target.clone());
                    }
                }
            }
        }

        result
    }

    /// Gets direct parents of a node.
    pub fn parents(&self, node_id: &str) -> Vec<&LineageNode> {
        self.edges_by_target
            .get(node_id)
            .map(|edges| {
                edges
                    .iter()
                    .filter_map(|e| self.nodes.get(&e.source))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets direct children of a node.
    pub fn children(&self, node_id: &str) -> Vec<&LineageNode> {
        self.edges_by_source
            .get(node_id)
            .map(|edges| {
                edges
                    .iter()
                    .filter_map(|e| self.nodes.get(&e.target))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets edges from a source node.
    pub fn edges_from(&self, source: &str) -> Vec<&LineageEdge> {
        self.edges_by_source
            .get(source)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Gets edges to a target node.
    pub fn edges_to(&self, target: &str) -> Vec<&LineageEdge> {
        self.edges_by_target
            .get(target)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Finds paths between two nodes.
    pub fn find_paths(&self, source: &str, target: &str, max_depth: usize) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        let mut current_path = vec![source.to_string()];
        self.find_paths_recursive(source, target, max_depth, &mut current_path, &mut paths);
        paths
    }

    fn find_paths_recursive(
        &self,
        current: &str,
        target: &str,
        remaining_depth: usize,
        path: &mut Vec<String>,
        paths: &mut Vec<Vec<String>>,
    ) {
        if current == target {
            paths.push(path.clone());
            return;
        }

        if remaining_depth == 0 {
            return;
        }

        if let Some(edges) = self.edges_by_source.get(current) {
            for edge in edges {
                if !path.contains(&edge.target) {
                    path.push(edge.target.clone());
                    self.find_paths_recursive(
                        &edge.target,
                        target,
                        remaining_depth - 1,
                        path,
                        paths,
                    );
                    path.pop();
                }
            }
        }
    }

    /// Returns all root nodes (nodes with no incoming edges).
    pub fn roots(&self) -> Vec<&LineageNode> {
        self.nodes
            .values()
            .filter(|n| !self.edges_by_target.contains_key(&n.id) ||
                        self.edges_by_target.get(&n.id).map_or(true, |e| e.is_empty()))
            .collect()
    }

    /// Returns all leaf nodes (nodes with no outgoing edges).
    pub fn leaves(&self) -> Vec<&LineageNode> {
        self.nodes
            .values()
            .filter(|n| !self.edges_by_source.contains_key(&n.id) ||
                        self.edges_by_source.get(&n.id).map_or(true, |e| e.is_empty()))
            .collect()
    }

    /// Gets all nodes.
    pub fn nodes(&self) -> impl Iterator<Item = &LineageNode> {
        self.nodes.values()
    }

    /// Gets all edges.
    pub fn edges(&self) -> impl Iterator<Item = &LineageEdge> {
        self.edges_by_source.values().flatten()
    }

    /// Returns the number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges_by_source.values().map(|v| v.len()).sum()
    }

    /// Finds nodes by type.
    pub fn nodes_by_type(&self, node_type: NodeType) -> Vec<&LineageNode> {
        self.nodes
            .values()
            .filter(|n| n.node_type == node_type)
            .collect()
    }

    /// Finds nodes by dataset ID.
    pub fn nodes_by_dataset(&self, dataset_id: &str) -> Vec<&LineageNode> {
        self.nodes
            .values()
            .filter(|n| n.dataset_id.as_deref() == Some(dataset_id))
            .collect()
    }

    /// Computes impact analysis (what would be affected if a node changes).
    pub fn impact_analysis(&self, node_id: &str) -> ImpactReport {
        let downstream = self.downstream(node_id);

        let mut affected_datasets = HashSet::new();
        let mut affected_models = HashSet::new();
        let mut affected_outputs = HashSet::new();

        for node in &downstream {
            match node.node_type {
                NodeType::Dataset => {
                    affected_datasets.insert(node.id.clone());
                }
                NodeType::Model => {
                    affected_models.insert(node.id.clone());
                }
                NodeType::Output => {
                    affected_outputs.insert(node.id.clone());
                }
                _ => {}
            }
        }

        ImpactReport {
            source_node: node_id.to_string(),
            total_affected: downstream.len(),
            affected_datasets: affected_datasets.into_iter().collect(),
            affected_models: affected_models.into_iter().collect(),
            affected_outputs: affected_outputs.into_iter().collect(),
        }
    }
}

/// Impact analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactReport {
    /// Source node that triggered analysis.
    pub source_node: String,
    /// Total number of affected nodes.
    pub total_affected: usize,
    /// Affected dataset IDs.
    pub affected_datasets: Vec<String>,
    /// Affected model IDs.
    pub affected_models: Vec<String>,
    /// Affected output IDs.
    pub affected_outputs: Vec<String>,
}

/// Lineage query builder.
pub struct LineageQuery<'a> {
    lineage: &'a Lineage,
    node_types: Option<Vec<NodeType>>,
    lineage_types: Option<Vec<LineageType>>,
    tags: Option<Vec<String>>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
}

impl<'a> LineageQuery<'a> {
    /// Creates a new query.
    pub fn new(lineage: &'a Lineage) -> Self {
        Self {
            lineage,
            node_types: None,
            lineage_types: None,
            tags: None,
            since: None,
            until: None,
        }
    }

    /// Filters by node types.
    #[must_use]
    pub fn node_types(mut self, types: Vec<NodeType>) -> Self {
        self.node_types = Some(types);
        self
    }

    /// Filters by lineage types.
    #[must_use]
    pub fn lineage_types(mut self, types: Vec<LineageType>) -> Self {
        self.lineage_types = Some(types);
        self
    }

    /// Filters by tags.
    #[must_use]
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = Some(tags);
        self
    }

    /// Filters by time range.
    #[must_use]
    pub fn time_range(mut self, since: DateTime<Utc>, until: DateTime<Utc>) -> Self {
        self.since = Some(since);
        self.until = Some(until);
        self
    }

    /// Executes the query and returns matching nodes.
    pub fn execute(&self) -> Vec<&LineageNode> {
        self.lineage
            .nodes
            .values()
            .filter(|node| {
                // Filter by node type
                if let Some(ref types) = self.node_types {
                    if !types.contains(&node.node_type) {
                        return false;
                    }
                }

                // Filter by tags
                if let Some(ref tags) = self.tags {
                    if !tags.iter().any(|t| node.tags.contains(t)) {
                        return false;
                    }
                }

                // Filter by time range
                if let Some(since) = self.since {
                    if node.created_at < since {
                        return false;
                    }
                }
                if let Some(until) = self.until {
                    if node.created_at > until {
                        return false;
                    }
                }

                true
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_lineage() -> Lineage {
        let mut lineage = Lineage::new();

        // Add nodes
        lineage.add_node(LineageNode::source("source1", "Raw Data")).unwrap();
        lineage.add_node(LineageNode::dataset("dataset1", "Processed", "ds-001")).unwrap();
        lineage.add_node(LineageNode::dataset("dataset2", "Enriched", "ds-002")).unwrap();
        lineage.add_node(LineageNode::model("model1", "ML Model")).unwrap();
        lineage.add_node(LineageNode::new("output1", "Predictions", NodeType::Output)).unwrap();

        // Add edges
        lineage.add_edge(LineageEdge::new("source1", "dataset1", LineageType::Imported)).unwrap();
        lineage.add_edge(LineageEdge::new("dataset1", "dataset2", LineageType::Derived)).unwrap();
        lineage.add_edge(LineageEdge::new("dataset2", "model1", LineageType::Training)).unwrap();
        lineage.add_edge(LineageEdge::new("model1", "output1", LineageType::Inference)).unwrap();

        lineage
    }

    #[test]
    fn test_add_nodes_and_edges() {
        let lineage = create_test_lineage();

        assert_eq!(lineage.node_count(), 5);
        assert_eq!(lineage.edge_count(), 4);
    }

    #[test]
    fn test_upstream_downstream() {
        let lineage = create_test_lineage();

        let upstream = lineage.upstream("model1");
        assert_eq!(upstream.len(), 3); // source1, dataset1, dataset2

        let downstream = lineage.downstream("source1");
        assert_eq!(downstream.len(), 4); // dataset1, dataset2, model1, output1
    }

    #[test]
    fn test_parents_children() {
        let lineage = create_test_lineage();

        let parents = lineage.parents("dataset2");
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].id, "dataset1");

        let children = lineage.children("dataset1");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].id, "dataset2");
    }

    #[test]
    fn test_roots_leaves() {
        let lineage = create_test_lineage();

        let roots = lineage.roots();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].id, "source1");

        let leaves = lineage.leaves();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].id, "output1");
    }

    #[test]
    fn test_cycle_detection() {
        let mut lineage = Lineage::new();

        lineage.add_node(LineageNode::source("a", "A")).unwrap();
        lineage.add_node(LineageNode::source("b", "B")).unwrap();
        lineage.add_node(LineageNode::source("c", "C")).unwrap();

        lineage.add_edge(LineageEdge::new("a", "b", LineageType::Derived)).unwrap();
        lineage.add_edge(LineageEdge::new("b", "c", LineageType::Derived)).unwrap();

        // This should fail - would create a cycle
        let result = lineage.add_edge(LineageEdge::new("c", "a", LineageType::Derived));
        assert!(result.is_err());
    }

    #[test]
    fn test_find_paths() {
        let lineage = create_test_lineage();

        let paths = lineage.find_paths("source1", "output1", 10);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec!["source1", "dataset1", "dataset2", "model1", "output1"]);
    }

    #[test]
    fn test_impact_analysis() {
        let lineage = create_test_lineage();

        let report = lineage.impact_analysis("dataset1");

        assert_eq!(report.total_affected, 3); // dataset2, model1, output1
        assert_eq!(report.affected_datasets.len(), 1);
        assert_eq!(report.affected_models.len(), 1);
        assert_eq!(report.affected_outputs.len(), 1);
    }

    #[test]
    fn test_nodes_by_type() {
        let lineage = create_test_lineage();

        let datasets = lineage.nodes_by_type(NodeType::Dataset);
        assert_eq!(datasets.len(), 2);
    }
}
