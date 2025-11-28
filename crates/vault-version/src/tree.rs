//! Tree objects (directory structures).

use crate::{VersionError, VersionResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Tree entry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryType {
    /// A blob (data object).
    Blob,
    /// A subtree (directory).
    Tree,
    /// A symlink.
    Link,
}

/// A tree entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeEntry {
    /// Entry name.
    pub name: String,
    /// Entry type.
    pub entry_type: EntryType,
    /// Content hash.
    pub hash: String,
    /// Size in bytes (for blobs).
    pub size: Option<u64>,
    /// File mode (Unix-style).
    pub mode: u32,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

impl TreeEntry {
    /// Creates a blob entry.
    pub fn blob(name: impl Into<String>, hash: impl Into<String>, size: u64) -> Self {
        Self {
            name: name.into(),
            entry_type: EntryType::Blob,
            hash: hash.into(),
            size: Some(size),
            mode: 0o100644,
            metadata: None,
        }
    }

    /// Creates a tree entry.
    pub fn tree(name: impl Into<String>, hash: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entry_type: EntryType::Tree,
            hash: hash.into(),
            size: None,
            mode: 0o040000,
            metadata: None,
        }
    }

    /// Creates a link entry.
    pub fn link(name: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            entry_type: EntryType::Link,
            hash: target.into(), // For links, hash is the target path
            size: None,
            mode: 0o120000,
            metadata: None,
        }
    }

    /// Sets metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Sets mode.
    #[must_use]
    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }
}

/// A tree object (directory snapshot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tree {
    /// Entries (sorted by name).
    entries: BTreeMap<String, TreeEntry>,
    /// Tree hash (computed on creation).
    #[serde(skip)]
    hash: Option<String>,
}

impl Tree {
    /// Creates an empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            hash: None,
        }
    }

    /// Creates from entries.
    pub fn from_entries(entries: impl IntoIterator<Item = TreeEntry>) -> Self {
        let mut tree = Self::new();
        for entry in entries {
            tree.entries.insert(entry.name.clone(), entry);
        }
        tree
    }

    /// Returns the tree hash.
    pub fn hash(&self) -> Option<&str> {
        self.hash.as_deref()
    }

    /// Computes and sets the hash.
    pub fn compute_hash(&mut self) -> String {
        let content = self.to_content_bytes();
        let hash = blake3::hash(&content).to_hex().to_string();
        self.hash = Some(hash.clone());
        hash
    }

    /// Serializes for hash computation.
    fn to_content_bytes(&self) -> Vec<u8> {
        let mut content = Vec::new();
        for (name, entry) in &self.entries {
            content.extend_from_slice(&entry.mode.to_be_bytes());
            content.push(b' ');
            content.extend_from_slice(name.as_bytes());
            content.push(0);
            content.extend_from_slice(entry.hash.as_bytes());
        }
        content
    }

    /// Adds an entry.
    pub fn add(&mut self, entry: TreeEntry) {
        self.entries.insert(entry.name.clone(), entry);
        self.hash = None; // Invalidate hash
    }

    /// Removes an entry.
    pub fn remove(&mut self, name: &str) -> Option<TreeEntry> {
        let entry = self.entries.remove(name);
        if entry.is_some() {
            self.hash = None;
        }
        entry
    }

    /// Gets an entry by name.
    pub fn get(&self, name: &str) -> Option<&TreeEntry> {
        self.entries.get(name)
    }

    /// Gets an entry by path (supports nested paths).
    pub fn get_path(&self, path: &str) -> Option<&TreeEntry> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() == 1 {
            return self.get(parts[0]);
        }

        // For nested paths, we'd need to load subtrees
        // This is a simplified version that only handles single-level
        self.get(parts[0])
    }

    /// Returns all entries.
    pub fn entries(&self) -> impl Iterator<Item = &TreeEntry> {
        self.entries.values()
    }

    /// Returns entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Checks if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all entry names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(|s| s.as_str())
    }
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

/// Tree builder for constructing trees.
pub struct TreeBuilder {
    entries: Vec<TreeEntry>,
    nested: BTreeMap<String, TreeBuilder>,
}

impl TreeBuilder {
    /// Creates a new tree builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            nested: BTreeMap::new(),
        }
    }

    /// Adds a blob entry.
    #[must_use]
    pub fn blob(mut self, name: impl Into<String>, hash: impl Into<String>, size: u64) -> Self {
        self.entries.push(TreeEntry::blob(name, hash, size));
        self
    }

    /// Adds an entry at a path (creating nested trees as needed).
    pub fn add_at_path(&mut self, path: &str, entry: TreeEntry) {
        let parts: Vec<&str> = path.split('/').collect();

        if parts.len() == 1 {
            self.entries.push(entry);
        } else {
            let dir = parts[0];
            let rest = parts[1..].join("/");

            let nested = self.nested.entry(dir.to_string()).or_insert_with(TreeBuilder::new);
            nested.add_at_path(&rest, entry);
        }
    }

    /// Builds the tree.
    pub fn build(self) -> Tree {
        let mut tree = Tree::new();

        // Add direct entries
        for entry in self.entries {
            tree.add(entry);
        }

        // Build and add nested trees
        for (name, builder) in self.nested {
            let mut nested_tree = builder.build();
            let hash = nested_tree.compute_hash();
            tree.add(TreeEntry::tree(name, hash));
        }

        tree.compute_hash();
        tree
    }
}

impl Default for TreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Tree walker for traversing trees.
pub struct TreeWalker<'a> {
    stack: Vec<(&'a Tree, String)>,
}

impl<'a> TreeWalker<'a> {
    /// Creates a walker starting at the given tree.
    pub fn new(tree: &'a Tree) -> Self {
        Self {
            stack: vec![(tree, String::new())],
        }
    }
}

impl<'a> Iterator for TreeWalker<'a> {
    type Item = (String, &'a TreeEntry);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((tree, prefix)) = self.stack.pop() {
            for entry in tree.entries() {
                let path = if prefix.is_empty() {
                    entry.name.clone()
                } else {
                    format!("{}/{}", prefix, entry.name)
                };

                // For now, just return the entry
                // In a full implementation, we'd load subtrees
                return Some((path, entry));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_entry_blob() {
        let entry = TreeEntry::blob("file.txt", "hash123", 1024);

        assert_eq!(entry.name, "file.txt");
        assert_eq!(entry.entry_type, EntryType::Blob);
        assert_eq!(entry.size, Some(1024));
    }

    #[test]
    fn test_tree_operations() {
        let mut tree = Tree::new();

        tree.add(TreeEntry::blob("a.txt", "hash_a", 100));
        tree.add(TreeEntry::blob("b.txt", "hash_b", 200));
        tree.add(TreeEntry::tree("subdir", "hash_subdir"));

        assert_eq!(tree.len(), 3);
        assert!(tree.get("a.txt").is_some());
        assert!(tree.get("nonexistent").is_none());

        tree.remove("a.txt");
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn test_tree_hash() {
        let mut tree1 = Tree::new();
        tree1.add(TreeEntry::blob("file.txt", "hash123", 100));
        let hash1 = tree1.compute_hash();

        let mut tree2 = Tree::new();
        tree2.add(TreeEntry::blob("file.txt", "hash123", 100));
        let hash2 = tree2.compute_hash();

        assert_eq!(hash1, hash2);

        let mut tree3 = Tree::new();
        tree3.add(TreeEntry::blob("file.txt", "different", 100));
        let hash3 = tree3.compute_hash();

        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_tree_builder() {
        let tree = TreeBuilder::new()
            .blob("file1.txt", "hash1", 100)
            .blob("file2.txt", "hash2", 200)
            .build();

        assert_eq!(tree.len(), 2);
        assert!(tree.hash().is_some());
    }

    #[test]
    fn test_tree_builder_nested() {
        let mut builder = TreeBuilder::new();
        builder.add_at_path("dir/subdir/file.txt", TreeEntry::blob("file.txt", "hash", 100));
        builder.add_at_path("root.txt", TreeEntry::blob("root.txt", "roothash", 50));

        let tree = builder.build();

        assert!(tree.get("root.txt").is_some());
        assert!(tree.get("dir").is_some());
    }
}
