# LLM-Data-Vault Pseudocode: Versioning & Lineage

**Document:** 07-versioning-lineage.md
**Version:** 1.0.0
**Phase:** SPARC - Pseudocode
**Last Updated:** 2025-11-27

---

## Overview

This document defines the versioning and lineage tracking system:
- Git-like versioning for datasets
- Content-addressable storage
- Branching, tagging, merging
- Data lineage and provenance tracking

---

## 1. Version Control Core

```rust
// src/versioning/mod.rs

// ============================================================================
// Core Version Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub id: VersionId,
    pub dataset_id: DatasetId,
    pub version_number: u64,
    pub commit: Commit,
    pub statistics: VersionStatistics,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    pub hash: ContentHash,
    pub tree_hash: ContentHash,
    pub parent_hashes: Vec<ContentHash>,
    pub author: CommitAuthor,
    pub committer: CommitAuthor,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub signature: Option<CommitSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitAuthor {
    pub user_id: UserId,
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitSignature {
    pub algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionStatistics {
    pub record_count: u64,
    pub total_size: ByteSize,
    pub added_records: u64,
    pub removed_records: u64,
    pub modified_records: u64,
    pub schema_version: Option<String>,
}

// ============================================================================
// Git-like Object Model
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GitObject {
    Blob(BlobObject),
    Tree(TreeObject),
    Commit(CommitObject),
    Tag(TagObject),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobObject {
    pub hash: ContentHash,
    pub size: u64,
    pub content_type: BlobType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BlobType {
    Record,
    Schema,
    Metadata,
    Chunk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeObject {
    pub hash: ContentHash,
    pub entries: Vec<TreeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEntry {
    pub mode: EntryMode,
    pub name: String,
    pub hash: ContentHash,
    pub entry_type: EntryType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EntryMode {
    File,      // 100644
    Directory, // 040000
    Symlink,   // 120000
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EntryType {
    Blob,
    Tree,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitObject {
    pub hash: ContentHash,
    pub tree: ContentHash,
    pub parents: Vec<ContentHash>,
    pub author: CommitAuthor,
    pub committer: CommitAuthor,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub gpg_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagObject {
    pub hash: ContentHash,
    pub name: String,
    pub target: ContentHash,
    pub target_type: ObjectType,
    pub tagger: Option<CommitAuthor>,
    pub message: Option<String>,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ObjectType {
    Blob,
    Tree,
    Commit,
    Tag,
}
```

---

## 2. Version Control Service

```rust
// src/versioning/service.rs

pub struct VersionControlService {
    object_store: Arc<dyn ObjectStore>,
    ref_store: Arc<dyn RefStore>,
    metrics: Arc<VersioningMetrics>,
}

impl VersionControlService {
    pub fn new(
        object_store: Arc<dyn ObjectStore>,
        ref_store: Arc<dyn RefStore>,
    ) -> Self {
        Self {
            object_store,
            ref_store,
            metrics: Arc::new(VersioningMetrics::new()),
        }
    }

    /// Create a new commit from staged changes
    pub async fn commit(
        &self,
        dataset_id: &DatasetId,
        changes: StagedChanges,
        message: &str,
        author: &CommitAuthor,
    ) -> Result<Commit, VersioningError> {
        let _timer = self.metrics.operation_timer("commit");

        // Build tree from changes
        let tree = self.build_tree(&changes).await?;
        let tree_hash = self.object_store.store_tree(&tree).await?;

        // Get parent commit(s)
        let head_ref = self.ref_store
            .get_head(dataset_id)
            .await?;

        let parent_hashes = match head_ref {
            Some(ref_info) => vec![ref_info.commit_hash],
            None => vec![],
        };

        // Create commit object
        let commit = CommitObject {
            hash: ContentHash::default(), // Will be computed
            tree: tree_hash,
            parents: parent_hashes.clone(),
            author: author.clone(),
            committer: author.clone(),
            message: message.to_string(),
            timestamp: Utc::now(),
            gpg_signature: None,
        };

        // Compute commit hash and store
        let commit_hash = self.compute_commit_hash(&commit);
        let mut stored_commit = commit.clone();
        stored_commit.hash = commit_hash.clone();

        self.object_store.store_commit(&stored_commit).await?;

        // Update HEAD reference
        self.ref_store
            .update_head(dataset_id, &commit_hash)
            .await?;

        self.metrics.record_commit();

        Ok(Commit {
            hash: commit_hash,
            tree_hash,
            parent_hashes,
            author: author.clone(),
            committer: author.clone(),
            message: message.to_string(),
            timestamp: Utc::now(),
            signature: None,
        })
    }

    /// Get commit by hash
    pub async fn get_commit(&self, hash: &ContentHash) -> Result<Option<CommitObject>, VersioningError> {
        self.object_store.get_commit(hash).await
    }

    /// Get commit history
    pub async fn log(
        &self,
        dataset_id: &DatasetId,
        options: LogOptions,
    ) -> Result<Vec<CommitObject>, VersioningError> {
        let head = self.ref_store.get_head(dataset_id).await?
            .ok_or(VersioningError::NoCommits)?;

        let mut commits = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(head.commit_hash);

        while let Some(hash) = queue.pop_front() {
            if visited.contains(&hash) {
                continue;
            }
            visited.insert(hash.clone());

            if let Some(commit) = self.object_store.get_commit(&hash).await? {
                // Apply filters
                if let Some(ref since) = options.since {
                    if commit.timestamp < *since {
                        continue;
                    }
                }
                if let Some(ref until) = options.until {
                    if commit.timestamp > *until {
                        continue;
                    }
                }
                if let Some(ref author) = options.author {
                    if commit.author.email != *author && commit.author.name != *author {
                        continue;
                    }
                }

                commits.push(commit.clone());

                // Add parents to queue
                for parent in &commit.parents {
                    queue.push_back(parent.clone());
                }

                // Check limit
                if let Some(limit) = options.limit {
                    if commits.len() >= limit {
                        break;
                    }
                }
            }
        }

        // Sort by timestamp (newest first)
        commits.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(commits)
    }

    /// Compute diff between two commits
    pub async fn diff(
        &self,
        from: &ContentHash,
        to: &ContentHash,
    ) -> Result<Diff, VersioningError> {
        let from_tree = self.get_tree_for_commit(from).await?;
        let to_tree = self.get_tree_for_commit(to).await?;

        let diff_engine = DiffEngine::new();
        diff_engine.compute_diff(&from_tree, &to_tree).await
    }

    async fn build_tree(&self, changes: &StagedChanges) -> Result<TreeObject, VersioningError> {
        let mut entries = Vec::new();

        for (path, change) in &changes.changes {
            match change {
                Change::Add(blob_hash) | Change::Modify(blob_hash) => {
                    entries.push(TreeEntry {
                        mode: EntryMode::File,
                        name: path.clone(),
                        hash: blob_hash.clone(),
                        entry_type: EntryType::Blob,
                    });
                }
                Change::Delete => {
                    // Don't include deleted entries
                }
            }
        }

        let tree = TreeObject {
            hash: ContentHash::default(),
            entries,
        };

        Ok(tree)
    }

    fn compute_commit_hash(&self, commit: &CommitObject) -> ContentHash {
        let mut hasher = blake3::Hasher::new();

        hasher.update(commit.tree.to_bytes());
        for parent in &commit.parents {
            hasher.update(parent.to_bytes());
        }
        hasher.update(commit.author.email.as_bytes());
        hasher.update(commit.message.as_bytes());
        hasher.update(&commit.timestamp.timestamp().to_le_bytes());

        ContentHash::from_bytes(hasher.finalize().as_bytes())
    }

    async fn get_tree_for_commit(&self, commit_hash: &ContentHash) -> Result<TreeObject, VersioningError> {
        let commit = self.object_store.get_commit(commit_hash).await?
            .ok_or(VersioningError::CommitNotFound { hash: commit_hash.clone() })?;

        self.object_store.get_tree(&commit.tree).await?
            .ok_or(VersioningError::TreeNotFound { hash: commit.tree })
    }
}

#[derive(Debug, Clone, Default)]
pub struct LogOptions {
    pub limit: Option<usize>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub author: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StagedChanges {
    pub changes: HashMap<String, Change>,
}

#[derive(Debug, Clone)]
pub enum Change {
    Add(ContentHash),
    Modify(ContentHash),
    Delete,
}
```

---

## 3. Branch Management

```rust
// src/versioning/branch.rs

pub struct BranchManager {
    ref_store: Arc<dyn RefStore>,
    object_store: Arc<dyn ObjectStore>,
    config: BranchConfig,
}

#[derive(Debug, Clone)]
pub struct BranchConfig {
    pub default_branch: String,
    pub protected_branches: Vec<String>,
    pub require_review_for_protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    pub name: String,
    pub dataset_id: DatasetId,
    pub commit_hash: ContentHash,
    pub is_default: bool,
    pub is_protected: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: UserId,
}

impl BranchManager {
    pub fn new(
        ref_store: Arc<dyn RefStore>,
        object_store: Arc<dyn ObjectStore>,
        config: BranchConfig,
    ) -> Self {
        Self { ref_store, object_store, config }
    }

    /// Create a new branch
    pub async fn create_branch(
        &self,
        dataset_id: &DatasetId,
        name: &str,
        from: BranchSource,
        created_by: &UserId,
    ) -> Result<Branch, VersioningError> {
        // Validate branch name
        self.validate_branch_name(name)?;

        // Check if branch already exists
        if self.ref_store.get_branch(dataset_id, name).await?.is_some() {
            return Err(VersioningError::BranchAlreadyExists { name: name.to_string() });
        }

        // Get source commit
        let commit_hash = match from {
            BranchSource::Head => {
                self.ref_store.get_head(dataset_id).await?
                    .ok_or(VersioningError::NoCommits)?
                    .commit_hash
            }
            BranchSource::Branch(ref branch_name) => {
                self.ref_store.get_branch(dataset_id, branch_name).await?
                    .ok_or(VersioningError::BranchNotFound { name: branch_name.clone() })?
                    .commit_hash
            }
            BranchSource::Commit(hash) => hash,
        };

        let now = Utc::now();
        let branch = Branch {
            name: name.to_string(),
            dataset_id: *dataset_id,
            commit_hash,
            is_default: false,
            is_protected: false,
            created_at: now,
            updated_at: now,
            created_by: *created_by,
        };

        self.ref_store.create_branch(&branch).await?;

        Ok(branch)
    }

    /// Delete a branch
    pub async fn delete_branch(
        &self,
        dataset_id: &DatasetId,
        name: &str,
    ) -> Result<(), VersioningError> {
        let branch = self.ref_store.get_branch(dataset_id, name).await?
            .ok_or(VersioningError::BranchNotFound { name: name.to_string() })?;

        if branch.is_default {
            return Err(VersioningError::CannotDeleteDefaultBranch);
        }

        if branch.is_protected {
            return Err(VersioningError::BranchProtected { name: name.to_string() });
        }

        self.ref_store.delete_branch(dataset_id, name).await
    }

    /// List all branches
    pub async fn list_branches(
        &self,
        dataset_id: &DatasetId,
    ) -> Result<Vec<Branch>, VersioningError> {
        self.ref_store.list_branches(dataset_id).await
    }

    /// Compare two branches
    pub async fn compare(
        &self,
        dataset_id: &DatasetId,
        base: &str,
        head: &str,
    ) -> Result<BranchComparison, VersioningError> {
        let base_branch = self.ref_store.get_branch(dataset_id, base).await?
            .ok_or(VersioningError::BranchNotFound { name: base.to_string() })?;

        let head_branch = self.ref_store.get_branch(dataset_id, head).await?
            .ok_or(VersioningError::BranchNotFound { name: head.to_string() })?;

        // Find merge base
        let merge_base = self.find_merge_base(&base_branch.commit_hash, &head_branch.commit_hash).await?;

        // Count commits ahead/behind
        let ahead = self.count_commits(&merge_base, &head_branch.commit_hash).await?;
        let behind = self.count_commits(&merge_base, &base_branch.commit_hash).await?;

        Ok(BranchComparison {
            base: base.to_string(),
            head: head.to_string(),
            merge_base,
            ahead,
            behind,
            can_merge: ahead > 0,
        })
    }

    /// Merge branches
    pub async fn merge(
        &self,
        dataset_id: &DatasetId,
        source: &str,
        target: &str,
        strategy: MergeStrategy,
        author: &CommitAuthor,
    ) -> Result<MergeResult, VersioningError> {
        let source_branch = self.ref_store.get_branch(dataset_id, source).await?
            .ok_or(VersioningError::BranchNotFound { name: source.to_string() })?;

        let target_branch = self.ref_store.get_branch(dataset_id, target).await?
            .ok_or(VersioningError::BranchNotFound { name: target.to_string() })?;

        if target_branch.is_protected && !self.config.require_review_for_protected {
            return Err(VersioningError::BranchProtected { name: target.to_string() });
        }

        // Find merge base
        let merge_base = self.find_merge_base(&source_branch.commit_hash, &target_branch.commit_hash).await?;

        // Check if fast-forward is possible
        if merge_base == target_branch.commit_hash {
            return self.fast_forward_merge(dataset_id, &source_branch, &target_branch).await;
        }

        match strategy {
            MergeStrategy::FastForward => {
                Err(VersioningError::FastForwardNotPossible)
            }
            MergeStrategy::ThreeWayMerge => {
                self.three_way_merge(dataset_id, &source_branch, &target_branch, &merge_base, author).await
            }
            MergeStrategy::Squash => {
                self.squash_merge(dataset_id, &source_branch, &target_branch, author).await
            }
        }
    }

    async fn fast_forward_merge(
        &self,
        dataset_id: &DatasetId,
        source: &Branch,
        target: &Branch,
    ) -> Result<MergeResult, VersioningError> {
        // Just update target branch to point to source commit
        self.ref_store.update_branch(dataset_id, &target.name, &source.commit_hash).await?;

        Ok(MergeResult {
            merge_type: MergeType::FastForward,
            commit_hash: source.commit_hash.clone(),
            conflicts: vec![],
        })
    }

    async fn three_way_merge(
        &self,
        dataset_id: &DatasetId,
        source: &Branch,
        target: &Branch,
        merge_base: &ContentHash,
        author: &CommitAuthor,
    ) -> Result<MergeResult, VersioningError> {
        // Get trees for all three commits
        let base_tree = self.get_tree_for_commit(merge_base).await?;
        let source_tree = self.get_tree_for_commit(&source.commit_hash).await?;
        let target_tree = self.get_tree_for_commit(&target.commit_hash).await?;

        // Compute three-way merge
        let merge_result = self.compute_three_way_merge(&base_tree, &source_tree, &target_tree).await?;

        if !merge_result.conflicts.is_empty() {
            return Ok(MergeResult {
                merge_type: MergeType::Conflicted,
                commit_hash: ContentHash::default(),
                conflicts: merge_result.conflicts,
            });
        }

        // Create merge commit
        let tree_hash = self.object_store.store_tree(&merge_result.merged_tree).await?;

        let commit = CommitObject {
            hash: ContentHash::default(),
            tree: tree_hash,
            parents: vec![target.commit_hash.clone(), source.commit_hash.clone()],
            author: author.clone(),
            committer: author.clone(),
            message: format!("Merge branch '{}' into '{}'", source.name, target.name),
            timestamp: Utc::now(),
            gpg_signature: None,
        };

        let commit_hash = self.compute_commit_hash(&commit);
        let mut stored_commit = commit;
        stored_commit.hash = commit_hash.clone();

        self.object_store.store_commit(&stored_commit).await?;
        self.ref_store.update_branch(dataset_id, &target.name, &commit_hash).await?;

        Ok(MergeResult {
            merge_type: MergeType::ThreeWay,
            commit_hash,
            conflicts: vec![],
        })
    }

    async fn squash_merge(
        &self,
        dataset_id: &DatasetId,
        source: &Branch,
        target: &Branch,
        author: &CommitAuthor,
    ) -> Result<MergeResult, VersioningError> {
        // Get source tree
        let source_tree = self.get_tree_for_commit(&source.commit_hash).await?;
        let tree_hash = self.object_store.store_tree(&source_tree).await?;

        // Create single commit on target
        let commit = CommitObject {
            hash: ContentHash::default(),
            tree: tree_hash,
            parents: vec![target.commit_hash.clone()],
            author: author.clone(),
            committer: author.clone(),
            message: format!("Squash merge branch '{}'", source.name),
            timestamp: Utc::now(),
            gpg_signature: None,
        };

        let commit_hash = self.compute_commit_hash(&commit);
        let mut stored_commit = commit;
        stored_commit.hash = commit_hash.clone();

        self.object_store.store_commit(&stored_commit).await?;
        self.ref_store.update_branch(dataset_id, &target.name, &commit_hash).await?;

        Ok(MergeResult {
            merge_type: MergeType::Squash,
            commit_hash,
            conflicts: vec![],
        })
    }

    fn validate_branch_name(&self, name: &str) -> Result<(), VersioningError> {
        if name.is_empty() {
            return Err(VersioningError::InvalidBranchName {
                name: name.to_string(),
                reason: "Branch name cannot be empty".to_string(),
            });
        }

        if name.contains("..") || name.starts_with('/') || name.ends_with('/') {
            return Err(VersioningError::InvalidBranchName {
                name: name.to_string(),
                reason: "Invalid characters in branch name".to_string(),
            });
        }

        Ok(())
    }

    async fn find_merge_base(
        &self,
        commit1: &ContentHash,
        commit2: &ContentHash,
    ) -> Result<ContentHash, VersioningError> {
        // Simple ancestor search (would use more efficient algorithm in production)
        let mut ancestors1 = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(commit1.clone());
        while let Some(hash) = queue.pop_front() {
            if ancestors1.contains(&hash) {
                continue;
            }
            ancestors1.insert(hash.clone());

            if let Some(commit) = self.object_store.get_commit(&hash).await? {
                for parent in commit.parents {
                    queue.push_back(parent);
                }
            }
        }

        // Find first common ancestor from commit2
        queue.clear();
        queue.push_back(commit2.clone());

        while let Some(hash) = queue.pop_front() {
            if ancestors1.contains(&hash) {
                return Ok(hash);
            }

            if let Some(commit) = self.object_store.get_commit(&hash).await? {
                for parent in commit.parents {
                    queue.push_back(parent);
                }
            }
        }

        Err(VersioningError::NoCommonAncestor)
    }

    async fn count_commits(&self, from: &ContentHash, to: &ContentHash) -> Result<usize, VersioningError> {
        let mut count = 0;
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(to.clone());

        while let Some(hash) = queue.pop_front() {
            if hash == *from || visited.contains(&hash) {
                continue;
            }
            visited.insert(hash.clone());
            count += 1;

            if let Some(commit) = self.object_store.get_commit(&hash).await? {
                for parent in commit.parents {
                    queue.push_back(parent);
                }
            }
        }

        Ok(count)
    }

    fn compute_commit_hash(&self, commit: &CommitObject) -> ContentHash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(commit.tree.to_bytes());
        for parent in &commit.parents {
            hasher.update(parent.to_bytes());
        }
        hasher.update(commit.message.as_bytes());
        hasher.update(&commit.timestamp.timestamp().to_le_bytes());
        ContentHash::from_bytes(hasher.finalize().as_bytes())
    }

    async fn get_tree_for_commit(&self, hash: &ContentHash) -> Result<TreeObject, VersioningError> {
        let commit = self.object_store.get_commit(hash).await?
            .ok_or(VersioningError::CommitNotFound { hash: hash.clone() })?;
        self.object_store.get_tree(&commit.tree).await?
            .ok_or(VersioningError::TreeNotFound { hash: commit.tree })
    }

    async fn compute_three_way_merge(
        &self,
        _base: &TreeObject,
        _source: &TreeObject,
        _target: &TreeObject,
    ) -> Result<ThreeWayMergeResult, VersioningError> {
        // Implement three-way merge algorithm
        todo!("Implement three-way merge")
    }
}

#[derive(Debug, Clone)]
pub enum BranchSource {
    Head,
    Branch(String),
    Commit(ContentHash),
}

#[derive(Debug, Clone)]
pub struct BranchComparison {
    pub base: String,
    pub head: String,
    pub merge_base: ContentHash,
    pub ahead: usize,
    pub behind: usize,
    pub can_merge: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum MergeStrategy {
    FastForward,
    ThreeWayMerge,
    Squash,
}

#[derive(Debug, Clone)]
pub struct MergeResult {
    pub merge_type: MergeType,
    pub commit_hash: ContentHash,
    pub conflicts: Vec<MergeConflict>,
}

#[derive(Debug, Clone, Copy)]
pub enum MergeType {
    FastForward,
    ThreeWay,
    Squash,
    Conflicted,
}

#[derive(Debug, Clone)]
pub struct MergeConflict {
    pub path: String,
    pub conflict_type: ConflictType,
    pub base_content: Option<ContentHash>,
    pub source_content: Option<ContentHash>,
    pub target_content: Option<ContentHash>,
}

#[derive(Debug, Clone, Copy)]
pub enum ConflictType {
    ModifyModify,
    AddAdd,
    ModifyDelete,
    DeleteModify,
}

struct ThreeWayMergeResult {
    merged_tree: TreeObject,
    conflicts: Vec<MergeConflict>,
}
```

---

## 4. Data Lineage Tracking

```rust
// src/lineage/mod.rs

pub struct LineageTracker {
    store: Arc<dyn LineageStore>,
    metrics: Arc<LineageMetrics>,
}

// ============================================================================
// Lineage Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageNode {
    pub id: LineageNodeId,
    pub entity: LineageEntity,
    pub created_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LineageEntity {
    Dataset { id: DatasetId, version: Option<VersionId> },
    Record { dataset_id: DatasetId, record_id: RecordId },
    Field { dataset_id: DatasetId, record_id: RecordId, field_name: String },
    ExternalSource { source_type: String, source_id: String },
    Transformation { name: String, version: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageEdge {
    pub id: Uuid,
    pub source: LineageNodeId,
    pub target: LineageNodeId,
    pub relationship: LineageRelationship,
    pub transformation: Option<TransformationInfo>,
    pub timestamp: DateTime<Utc>,
    pub actor: Option<UserId>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LineageRelationship {
    DerivedFrom,
    TransformedFrom,
    CopiedFrom,
    MergedFrom,
    FilteredFrom,
    AggregatedFrom,
    AnonymizedFrom,
    SampledFrom,
    JoinedFrom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationInfo {
    pub name: String,
    pub version: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub code_hash: Option<ContentHash>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageGraph {
    pub nodes: Vec<LineageNode>,
    pub edges: Vec<LineageEdge>,
    pub root: LineageNodeId,
}

// ============================================================================
// Lineage Tracker Implementation
// ============================================================================

impl LineageTracker {
    pub fn new(store: Arc<dyn LineageStore>) -> Self {
        Self {
            store,
            metrics: Arc::new(LineageMetrics::new()),
        }
    }

    /// Record a lineage relationship
    pub async fn record(
        &self,
        edge: LineageEdge,
    ) -> Result<(), LineageError> {
        let _timer = self.metrics.operation_timer("record_lineage");

        // Ensure source and target nodes exist
        if !self.store.node_exists(&edge.source).await? {
            return Err(LineageError::NodeNotFound { id: edge.source });
        }
        if !self.store.node_exists(&edge.target).await? {
            return Err(LineageError::NodeNotFound { id: edge.target });
        }

        self.store.create_edge(&edge).await?;
        self.metrics.record_edge_created();

        Ok(())
    }

    /// Record lineage for dataset derivation
    pub async fn record_derivation(
        &self,
        source_dataset: &DatasetId,
        source_version: Option<&VersionId>,
        target_dataset: &DatasetId,
        target_version: Option<&VersionId>,
        transformation: Option<TransformationInfo>,
        actor: &UserId,
    ) -> Result<(), LineageError> {
        let source_node = self.get_or_create_dataset_node(source_dataset, source_version).await?;
        let target_node = self.get_or_create_dataset_node(target_dataset, target_version).await?;

        let edge = LineageEdge {
            id: Uuid::new_v4(),
            source: source_node,
            target: target_node,
            relationship: LineageRelationship::DerivedFrom,
            transformation,
            timestamp: Utc::now(),
            actor: Some(*actor),
            metadata: HashMap::new(),
        };

        self.record(edge).await
    }

    /// Record lineage for anonymization
    pub async fn record_anonymization(
        &self,
        source_dataset: &DatasetId,
        target_dataset: &DatasetId,
        policy: &AnonymizationPolicy,
        actor: &UserId,
    ) -> Result<(), LineageError> {
        let source_node = self.get_or_create_dataset_node(source_dataset, None).await?;
        let target_node = self.get_or_create_dataset_node(target_dataset, None).await?;

        let transformation = TransformationInfo {
            name: "anonymization".to_string(),
            version: "1.0".to_string(),
            parameters: serde_json::to_value(&policy).ok()
                .map(|v| [("policy".to_string(), v)].into_iter().collect())
                .unwrap_or_default(),
            code_hash: None,
        };

        let edge = LineageEdge {
            id: Uuid::new_v4(),
            source: source_node,
            target: target_node,
            relationship: LineageRelationship::AnonymizedFrom,
            transformation: Some(transformation),
            timestamp: Utc::now(),
            actor: Some(*actor),
            metadata: HashMap::new(),
        };

        self.record(edge).await
    }

    /// Get upstream lineage (where did this data come from?)
    pub async fn get_upstream(
        &self,
        node_id: &LineageNodeId,
        depth: usize,
    ) -> Result<LineageGraph, LineageError> {
        self.traverse(node_id, depth, TraversalDirection::Upstream).await
    }

    /// Get downstream lineage (what depends on this data?)
    pub async fn get_downstream(
        &self,
        node_id: &LineageNodeId,
        depth: usize,
    ) -> Result<LineageGraph, LineageError> {
        self.traverse(node_id, depth, TraversalDirection::Downstream).await
    }

    /// Get full lineage graph
    pub async fn get_full_lineage(
        &self,
        node_id: &LineageNodeId,
    ) -> Result<LineageGraph, LineageError> {
        let upstream = self.get_upstream(node_id, usize::MAX).await?;
        let downstream = self.get_downstream(node_id, usize::MAX).await?;

        // Merge graphs
        let mut nodes = upstream.nodes;
        let mut edges = upstream.edges;

        for node in downstream.nodes {
            if !nodes.iter().any(|n| n.id == node.id) {
                nodes.push(node);
            }
        }
        for edge in downstream.edges {
            if !edges.iter().any(|e| e.id == edge.id) {
                edges.push(edge);
            }
        }

        Ok(LineageGraph {
            nodes,
            edges,
            root: *node_id,
        })
    }

    /// Impact analysis: what would be affected if this changes?
    pub async fn impact_analysis(
        &self,
        node_id: &LineageNodeId,
    ) -> Result<ImpactAnalysis, LineageError> {
        let downstream = self.get_downstream(node_id, usize::MAX).await?;

        let affected_datasets: Vec<_> = downstream.nodes
            .iter()
            .filter_map(|n| match &n.entity {
                LineageEntity::Dataset { id, .. } => Some(*id),
                _ => None,
            })
            .collect();

        let affected_records: Vec<_> = downstream.nodes
            .iter()
            .filter_map(|n| match &n.entity {
                LineageEntity::Record { record_id, .. } => Some(*record_id),
                _ => None,
            })
            .collect();

        Ok(ImpactAnalysis {
            source_node: *node_id,
            total_affected_nodes: downstream.nodes.len(),
            affected_datasets,
            affected_records,
            propagation_paths: self.extract_paths(&downstream),
        })
    }

    async fn traverse(
        &self,
        start: &LineageNodeId,
        max_depth: usize,
        direction: TraversalDirection,
    ) -> Result<LineageGraph, LineageError> {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut visited = HashSet::new();
        let mut queue: VecDeque<(LineageNodeId, usize)> = VecDeque::new();

        queue.push_back((*start, 0));

        while let Some((node_id, depth)) = queue.pop_front() {
            if visited.contains(&node_id) || depth > max_depth {
                continue;
            }
            visited.insert(node_id);

            if let Some(node) = self.store.get_node(&node_id).await? {
                nodes.push(node);
            }

            let related_edges = match direction {
                TraversalDirection::Upstream => {
                    self.store.get_incoming_edges(&node_id).await?
                }
                TraversalDirection::Downstream => {
                    self.store.get_outgoing_edges(&node_id).await?
                }
            };

            for edge in related_edges {
                edges.push(edge.clone());

                let next_node = match direction {
                    TraversalDirection::Upstream => edge.source,
                    TraversalDirection::Downstream => edge.target,
                };

                queue.push_back((next_node, depth + 1));
            }
        }

        Ok(LineageGraph {
            nodes,
            edges,
            root: *start,
        })
    }

    async fn get_or_create_dataset_node(
        &self,
        dataset_id: &DatasetId,
        version_id: Option<&VersionId>,
    ) -> Result<LineageNodeId, LineageError> {
        let entity = LineageEntity::Dataset {
            id: *dataset_id,
            version: version_id.copied(),
        };

        // Check if node already exists
        if let Some(existing) = self.store.find_node(&entity).await? {
            return Ok(existing.id);
        }

        // Create new node
        let node = LineageNode {
            id: LineageNodeId(Uuid::new_v4()),
            entity,
            created_at: Utc::now(),
            metadata: HashMap::new(),
        };

        self.store.create_node(&node).await?;

        Ok(node.id)
    }

    fn extract_paths(&self, graph: &LineageGraph) -> Vec<Vec<LineageNodeId>> {
        // Extract unique paths through the graph
        // Simplified implementation
        vec![]
    }
}

#[derive(Debug, Clone, Copy)]
enum TraversalDirection {
    Upstream,
    Downstream,
}

#[derive(Debug, Clone)]
pub struct ImpactAnalysis {
    pub source_node: LineageNodeId,
    pub total_affected_nodes: usize,
    pub affected_datasets: Vec<DatasetId>,
    pub affected_records: Vec<RecordId>,
    pub propagation_paths: Vec<Vec<LineageNodeId>>,
}

// ============================================================================
// Lineage Store Trait
// ============================================================================

#[async_trait]
pub trait LineageStore: Send + Sync {
    async fn create_node(&self, node: &LineageNode) -> Result<(), LineageError>;
    async fn get_node(&self, id: &LineageNodeId) -> Result<Option<LineageNode>, LineageError>;
    async fn find_node(&self, entity: &LineageEntity) -> Result<Option<LineageNode>, LineageError>;
    async fn node_exists(&self, id: &LineageNodeId) -> Result<bool, LineageError>;

    async fn create_edge(&self, edge: &LineageEdge) -> Result<(), LineageError>;
    async fn get_incoming_edges(&self, node_id: &LineageNodeId) -> Result<Vec<LineageEdge>, LineageError>;
    async fn get_outgoing_edges(&self, node_id: &LineageNodeId) -> Result<Vec<LineageEdge>, LineageError>;
}

#[derive(Debug, thiserror::Error)]
pub enum LineageError {
    #[error("Node not found: {id:?}")]
    NodeNotFound { id: LineageNodeId },

    #[error("Store error: {message}")]
    StoreError { message: String },
}
```

---

## Summary

This document defines the versioning and lineage system for LLM-Data-Vault:

| Component | Purpose |
|-----------|---------|
| **Version Control** | Git-like commits with content addressing |
| **Branch Management** | Branching, merging, comparisons |
| **Lineage Tracker** | Data provenance and impact analysis |

**Key Features:**
- Content-addressable object storage
- Merkle tree integrity verification
- Three-way merge with conflict detection
- Full upstream/downstream lineage
- Impact analysis for changes

---

*Next Document: [08-integration-observability.md](./08-integration-observability.md)*
