//! Branch and reference management.

use crate::{CommitId, VersionError, VersionResult};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Reference type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefType {
    /// Branch reference.
    Branch,
    /// Tag reference.
    Tag,
    /// Remote tracking branch.
    RemoteTracking,
}

/// A branch reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    /// Branch name.
    pub name: String,
    /// Current commit ID.
    pub commit: CommitId,
    /// Reference type.
    pub ref_type: RefType,
    /// Is protected (cannot be force-pushed or deleted).
    pub protected: bool,
    /// Description.
    pub description: Option<String>,
    /// Created timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Updated timestamp.
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Creator user ID.
    pub created_by: Option<String>,
}

impl Branch {
    /// Creates a new branch.
    pub fn new(name: impl Into<String>, commit: CommitId) -> Self {
        let now = chrono::Utc::now();
        Self {
            name: name.into(),
            commit,
            ref_type: RefType::Branch,
            protected: false,
            description: None,
            created_at: now,
            updated_at: now,
            created_by: None,
        }
    }

    /// Creates a tag.
    pub fn tag(name: impl Into<String>, commit: CommitId) -> Self {
        let mut branch = Self::new(name, commit);
        branch.ref_type = RefType::Tag;
        branch.protected = true; // Tags are immutable by default
        branch
    }

    /// Sets description.
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Sets protection.
    #[must_use]
    pub fn with_protection(mut self, protected: bool) -> Self {
        self.protected = protected;
        self
    }

    /// Sets creator.
    #[must_use]
    pub fn created_by(mut self, user_id: impl Into<String>) -> Self {
        self.created_by = Some(user_id.into());
        self
    }

    /// Returns the full reference path.
    #[must_use]
    pub fn ref_path(&self) -> String {
        match self.ref_type {
            RefType::Branch => format!("refs/heads/{}", self.name),
            RefType::Tag => format!("refs/tags/{}", self.name),
            RefType::RemoteTracking => format!("refs/remotes/{}", self.name),
        }
    }
}

/// Branch manager.
pub struct BranchManager {
    /// Branches by name.
    branches: RwLock<HashMap<String, Branch>>,
    /// Tags by name.
    tags: RwLock<HashMap<String, Branch>>,
    /// HEAD reference (current branch name or detached commit).
    head: RwLock<HeadRef>,
    /// Default branch name.
    default_branch: String,
}

/// HEAD reference.
#[derive(Debug, Clone)]
pub enum HeadRef {
    /// Points to a branch.
    Branch(String),
    /// Detached HEAD (direct commit).
    Detached(CommitId),
}

impl BranchManager {
    /// Creates a new branch manager.
    pub fn new(default_branch: impl Into<String>) -> Self {
        let default = default_branch.into();
        Self {
            branches: RwLock::new(HashMap::new()),
            tags: RwLock::new(HashMap::new()),
            head: RwLock::new(HeadRef::Branch(default.clone())),
            default_branch: default,
        }
    }

    /// Creates a new branch.
    pub fn create_branch(&self, name: &str, commit: CommitId) -> VersionResult<Branch> {
        let mut branches = self.branches.write();

        if branches.contains_key(name) {
            return Err(VersionError::RefExists(format!("Branch '{}' already exists", name)));
        }

        let branch = Branch::new(name, commit);
        branches.insert(name.to_string(), branch.clone());

        Ok(branch)
    }

    /// Creates a tag.
    pub fn create_tag(
        &self,
        name: &str,
        commit: CommitId,
        message: Option<&str>,
    ) -> VersionResult<Branch> {
        let mut tags = self.tags.write();

        if tags.contains_key(name) {
            return Err(VersionError::RefExists(format!("Tag '{}' already exists", name)));
        }

        let mut tag = Branch::tag(name, commit);
        if let Some(msg) = message {
            tag = tag.with_description(msg);
        }
        tags.insert(name.to_string(), tag.clone());

        Ok(tag)
    }

    /// Gets a branch by name.
    pub fn get_branch(&self, name: &str) -> Option<Branch> {
        self.branches.read().get(name).cloned()
    }

    /// Gets a tag by name.
    pub fn get_tag(&self, name: &str) -> Option<Branch> {
        self.tags.read().get(name).cloned()
    }

    /// Updates a branch to point to a new commit.
    pub fn update_branch(&self, name: &str, commit: CommitId, force: bool) -> VersionResult<()> {
        let mut branches = self.branches.write();

        let branch = branches.get_mut(name).ok_or_else(|| {
            VersionError::BranchNotFound(name.to_string())
        })?;

        if branch.protected && !force {
            return Err(VersionError::BranchProtected(name.to_string()));
        }

        branch.commit = commit;
        branch.updated_at = chrono::Utc::now();

        Ok(())
    }

    /// Deletes a branch.
    pub fn delete_branch(&self, name: &str, force: bool) -> VersionResult<()> {
        let mut branches = self.branches.write();

        if let Some(branch) = branches.get(name) {
            if branch.protected && !force {
                return Err(VersionError::BranchProtected(name.to_string()));
            }

            // Cannot delete current branch
            let head = self.head.read();
            if let HeadRef::Branch(current) = &*head {
                if current == name {
                    return Err(VersionError::BranchProtected(
                        "Cannot delete current branch".to_string(),
                    ));
                }
            }
        }

        branches.remove(name);
        Ok(())
    }

    /// Deletes a tag.
    pub fn delete_tag(&self, name: &str) -> VersionResult<()> {
        self.tags.write().remove(name);
        Ok(())
    }

    /// Renames a branch.
    pub fn rename_branch(&self, old_name: &str, new_name: &str) -> VersionResult<()> {
        let mut branches = self.branches.write();

        if branches.contains_key(new_name) {
            return Err(VersionError::RefExists(format!(
                "Branch '{}' already exists",
                new_name
            )));
        }

        let branch = branches.remove(old_name).ok_or_else(|| {
            VersionError::BranchNotFound(old_name.to_string())
        })?;

        let mut new_branch = branch;
        new_branch.name = new_name.to_string();
        new_branch.updated_at = chrono::Utc::now();

        branches.insert(new_name.to_string(), new_branch);

        // Update HEAD if needed
        let mut head = self.head.write();
        if let HeadRef::Branch(ref current) = *head {
            if current == old_name {
                *head = HeadRef::Branch(new_name.to_string());
            }
        }

        Ok(())
    }

    /// Lists all branches.
    pub fn list_branches(&self) -> Vec<Branch> {
        self.branches.read().values().cloned().collect()
    }

    /// Lists all tags.
    pub fn list_tags(&self) -> Vec<Branch> {
        self.tags.read().values().cloned().collect()
    }

    /// Gets the current HEAD reference.
    pub fn head(&self) -> HeadRef {
        self.head.read().clone()
    }

    /// Gets the current commit ID.
    pub fn head_commit(&self) -> Option<CommitId> {
        match &*self.head.read() {
            HeadRef::Branch(name) => {
                self.branches.read().get(name).map(|b| b.commit.clone())
            }
            HeadRef::Detached(commit) => Some(commit.clone()),
        }
    }

    /// Checks out a branch.
    pub fn checkout_branch(&self, name: &str) -> VersionResult<CommitId> {
        let branches = self.branches.read();
        let branch = branches.get(name).ok_or_else(|| {
            VersionError::BranchNotFound(name.to_string())
        })?;

        let commit = branch.commit.clone();
        drop(branches);

        *self.head.write() = HeadRef::Branch(name.to_string());

        Ok(commit)
    }

    /// Checks out a commit (detached HEAD).
    pub fn checkout_commit(&self, commit: CommitId) {
        *self.head.write() = HeadRef::Detached(commit);
    }

    /// Resolves a reference to a commit ID.
    pub fn resolve(&self, ref_name: &str) -> VersionResult<CommitId> {
        // Check if it's HEAD
        if ref_name == "HEAD" {
            return self.head_commit().ok_or_else(|| {
                VersionError::InvalidRef("HEAD not set".to_string())
            });
        }

        // Check branches
        if let Some(branch) = self.branches.read().get(ref_name) {
            return Ok(branch.commit.clone());
        }

        // Check tags
        if let Some(tag) = self.tags.read().get(ref_name) {
            return Ok(tag.commit.clone());
        }

        // Check if it's a full ref path
        if let Some(name) = ref_name.strip_prefix("refs/heads/") {
            if let Some(branch) = self.branches.read().get(name) {
                return Ok(branch.commit.clone());
            }
        }

        if let Some(name) = ref_name.strip_prefix("refs/tags/") {
            if let Some(tag) = self.tags.read().get(name) {
                return Ok(tag.commit.clone());
            }
        }

        // Try to parse as commit ID
        ref_name
            .parse::<CommitId>()
            .map_err(|_| VersionError::InvalidRef(ref_name.to_string()))
    }

    /// Protects a branch.
    pub fn protect_branch(&self, name: &str) -> VersionResult<()> {
        let mut branches = self.branches.write();
        let branch = branches.get_mut(name).ok_or_else(|| {
            VersionError::BranchNotFound(name.to_string())
        })?;
        branch.protected = true;
        Ok(())
    }

    /// Unprotects a branch.
    pub fn unprotect_branch(&self, name: &str) -> VersionResult<()> {
        let mut branches = self.branches.write();
        let branch = branches.get_mut(name).ok_or_else(|| {
            VersionError::BranchNotFound(name.to_string())
        })?;
        branch.protected = false;
        Ok(())
    }

    /// Returns the default branch name.
    #[must_use]
    pub fn default_branch(&self) -> &str {
        &self.default_branch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_manager() -> BranchManager {
        BranchManager::new("main")
    }

    #[test]
    fn test_create_branch() {
        let manager = create_manager();
        let commit = CommitId::from_hash("abc123456789012");

        let branch = manager.create_branch("feature", commit.clone()).unwrap();

        assert_eq!(branch.name, "feature");
        assert_eq!(branch.commit, commit);
        assert!(!branch.protected);
    }

    #[test]
    fn test_create_tag() {
        let manager = create_manager();
        let commit = CommitId::from_hash("abc123456789012");

        let tag = manager.create_tag("v1.0.0", commit.clone(), Some("Release 1.0")).unwrap();

        assert_eq!(tag.name, "v1.0.0");
        assert!(tag.protected);
        assert_eq!(tag.description, Some("Release 1.0".to_string()));
    }

    #[test]
    fn test_checkout() {
        let manager = create_manager();
        let commit = CommitId::from_hash("abc123456789012");

        manager.create_branch("main", commit.clone()).unwrap();
        manager.checkout_branch("main").unwrap();

        assert!(matches!(manager.head(), HeadRef::Branch(ref n) if n == "main"));
        assert_eq!(manager.head_commit(), Some(commit));
    }

    #[test]
    fn test_protected_branch() {
        let manager = create_manager();
        let commit = CommitId::from_hash("abc123456789012");

        manager.create_branch("main", commit).unwrap();
        manager.protect_branch("main").unwrap();

        let result = manager.delete_branch("main", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve() {
        let manager = create_manager();
        let commit = CommitId::from_hash("abc123456789012");

        manager.create_branch("main", commit.clone()).unwrap();
        manager.create_tag("v1.0", commit.clone(), None).unwrap();

        assert_eq!(manager.resolve("main").unwrap(), commit);
        assert_eq!(manager.resolve("v1.0").unwrap(), commit);
        assert_eq!(manager.resolve("refs/heads/main").unwrap(), commit);
    }
}
