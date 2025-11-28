//! Diff computation between trees/commits.

use crate::{Tree, TreeEntry, EntryType, VersionResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Diff type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffType {
    /// Entry added.
    Added,
    /// Entry deleted.
    Deleted,
    /// Entry modified.
    Modified,
    /// Entry renamed.
    Renamed,
    /// Entry copied.
    Copied,
    /// Type changed (e.g., file to directory).
    TypeChanged,
}

/// A diff entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    /// Path of the entry.
    pub path: String,
    /// Diff type.
    pub diff_type: DiffType,
    /// Old entry (for modified/deleted).
    pub old: Option<TreeEntry>,
    /// New entry (for modified/added).
    pub new: Option<TreeEntry>,
    /// Old path (for renamed).
    pub old_path: Option<String>,
    /// Similarity score (0-100, for renamed/copied).
    pub similarity: Option<u8>,
}

impl DiffEntry {
    /// Creates an added entry.
    pub fn added(path: impl Into<String>, entry: TreeEntry) -> Self {
        Self {
            path: path.into(),
            diff_type: DiffType::Added,
            old: None,
            new: Some(entry),
            old_path: None,
            similarity: None,
        }
    }

    /// Creates a deleted entry.
    pub fn deleted(path: impl Into<String>, entry: TreeEntry) -> Self {
        Self {
            path: path.into(),
            diff_type: DiffType::Deleted,
            old: Some(entry),
            new: None,
            old_path: None,
            similarity: None,
        }
    }

    /// Creates a modified entry.
    pub fn modified(path: impl Into<String>, old: TreeEntry, new: TreeEntry) -> Self {
        Self {
            path: path.into(),
            diff_type: DiffType::Modified,
            old: Some(old),
            new: Some(new),
            old_path: None,
            similarity: None,
        }
    }

    /// Creates a renamed entry.
    pub fn renamed(
        old_path: impl Into<String>,
        new_path: impl Into<String>,
        entry: TreeEntry,
        similarity: u8,
    ) -> Self {
        Self {
            path: new_path.into(),
            diff_type: DiffType::Renamed,
            old: Some(entry.clone()),
            new: Some(entry),
            old_path: Some(old_path.into()),
            similarity: Some(similarity),
        }
    }

    /// Returns true if this is an addition.
    #[must_use]
    pub fn is_added(&self) -> bool {
        self.diff_type == DiffType::Added
    }

    /// Returns true if this is a deletion.
    #[must_use]
    pub fn is_deleted(&self) -> bool {
        self.diff_type == DiffType::Deleted
    }

    /// Returns true if this is a modification.
    #[must_use]
    pub fn is_modified(&self) -> bool {
        self.diff_type == DiffType::Modified
    }

    /// Returns the size change.
    #[must_use]
    pub fn size_change(&self) -> i64 {
        let old_size = self.old.as_ref().and_then(|e| e.size).unwrap_or(0) as i64;
        let new_size = self.new.as_ref().and_then(|e| e.size).unwrap_or(0) as i64;
        new_size - old_size
    }
}

/// Diff options.
#[derive(Debug, Clone)]
pub struct DiffOptions {
    /// Detect renames.
    pub detect_renames: bool,
    /// Rename similarity threshold (0-100).
    pub rename_threshold: u8,
    /// Detect copies.
    pub detect_copies: bool,
    /// Include unchanged entries.
    pub include_unchanged: bool,
    /// Ignore whitespace changes.
    pub ignore_whitespace: bool,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            detect_renames: true,
            rename_threshold: 50,
            detect_copies: false,
            include_unchanged: false,
            ignore_whitespace: false,
        }
    }
}

/// A diff between two trees.
#[derive(Debug, Clone)]
pub struct Diff {
    /// Diff entries.
    pub entries: Vec<DiffEntry>,
    /// Statistics.
    pub stats: DiffStats,
}

/// Diff statistics.
#[derive(Debug, Clone, Default)]
pub struct DiffStats {
    /// Number of files added.
    pub added: usize,
    /// Number of files deleted.
    pub deleted: usize,
    /// Number of files modified.
    pub modified: usize,
    /// Number of files renamed.
    pub renamed: usize,
    /// Total insertions (bytes added).
    pub insertions: u64,
    /// Total deletions (bytes removed).
    pub deletions: u64,
}

impl DiffStats {
    /// Returns total files changed.
    #[must_use]
    pub fn total_changed(&self) -> usize {
        self.added + self.deleted + self.modified + self.renamed
    }
}

impl Diff {
    /// Computes diff between two trees.
    pub fn compute(old: &Tree, new: &Tree, options: &DiffOptions) -> Self {
        let mut entries = Vec::new();
        let mut stats = DiffStats::default();

        let old_names: HashSet<&str> = old.names().collect();
        let new_names: HashSet<&str> = new.names().collect();

        // Find deleted entries
        let deleted: Vec<&str> = old_names.difference(&new_names).copied().collect();
        let mut deleted_entries: HashMap<String, TreeEntry> = HashMap::new();

        for name in deleted {
            if let Some(entry) = old.get(name) {
                deleted_entries.insert(name.to_string(), entry.clone());
            }
        }

        // Find added entries
        let added: Vec<&str> = new_names.difference(&old_names).copied().collect();
        let mut added_entries: HashMap<String, TreeEntry> = HashMap::new();

        for name in added {
            if let Some(entry) = new.get(name) {
                added_entries.insert(name.to_string(), entry.clone());
            }
        }

        // Detect renames
        if options.detect_renames {
            let mut renames: Vec<(String, String, TreeEntry, u8)> = Vec::new();

            for (del_name, del_entry) in &deleted_entries {
                if del_entry.entry_type != EntryType::Blob {
                    continue;
                }

                for (add_name, add_entry) in &added_entries {
                    if add_entry.entry_type != EntryType::Blob {
                        continue;
                    }

                    // Check if content is the same (100% similarity)
                    if del_entry.hash == add_entry.hash {
                        renames.push((
                            del_name.clone(),
                            add_name.clone(),
                            add_entry.clone(),
                            100,
                        ));
                        break;
                    }
                }
            }

            // Remove renamed entries from added/deleted
            for (old_path, new_path, entry, similarity) in renames {
                deleted_entries.remove(&old_path);
                added_entries.remove(&new_path);
                entries.push(DiffEntry::renamed(old_path, new_path, entry, similarity));
                stats.renamed += 1;
            }
        }

        // Process remaining deleted
        for (name, entry) in deleted_entries {
            if entry.entry_type == EntryType::Blob {
                stats.deletions += entry.size.unwrap_or(0);
            }
            entries.push(DiffEntry::deleted(name, entry));
            stats.deleted += 1;
        }

        // Process remaining added
        for (name, entry) in added_entries {
            if entry.entry_type == EntryType::Blob {
                stats.insertions += entry.size.unwrap_or(0);
            }
            entries.push(DiffEntry::added(name, entry));
            stats.added += 1;
        }

        // Find modified entries
        for name in old_names.intersection(&new_names) {
            let old_entry = old.get(name).unwrap();
            let new_entry = new.get(name).unwrap();

            if old_entry.hash != new_entry.hash || old_entry.entry_type != new_entry.entry_type {
                let diff_type = if old_entry.entry_type != new_entry.entry_type {
                    DiffType::TypeChanged
                } else {
                    DiffType::Modified
                };

                let mut diff_entry = DiffEntry::modified(*name, old_entry.clone(), new_entry.clone());
                diff_entry.diff_type = diff_type;

                // Calculate size changes
                let old_size = old_entry.size.unwrap_or(0);
                let new_size = new_entry.size.unwrap_or(0);
                if new_size > old_size {
                    stats.insertions += new_size - old_size;
                } else {
                    stats.deletions += old_size - new_size;
                }

                entries.push(diff_entry);
                stats.modified += 1;
            }
        }

        // Sort entries by path
        entries.sort_by(|a, b| a.path.cmp(&b.path));

        Self { entries, stats }
    }

    /// Returns true if there are no changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of changes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Filters entries by type.
    pub fn filter_by_type(&self, diff_type: DiffType) -> Vec<&DiffEntry> {
        self.entries
            .iter()
            .filter(|e| e.diff_type == diff_type)
            .collect()
    }

    /// Returns added entries.
    pub fn added(&self) -> Vec<&DiffEntry> {
        self.filter_by_type(DiffType::Added)
    }

    /// Returns deleted entries.
    pub fn deleted(&self) -> Vec<&DiffEntry> {
        self.filter_by_type(DiffType::Deleted)
    }

    /// Returns modified entries.
    pub fn modified(&self) -> Vec<&DiffEntry> {
        self.filter_by_type(DiffType::Modified)
    }
}

/// Three-way merge result.
#[derive(Debug, Clone)]
pub struct MergeResult {
    /// Merged tree (if successful).
    pub tree: Option<Tree>,
    /// Conflicts.
    pub conflicts: Vec<MergeConflict>,
    /// Is clean merge (no conflicts).
    pub clean: bool,
}

/// A merge conflict.
#[derive(Debug, Clone)]
pub struct MergeConflict {
    /// Path of conflicting entry.
    pub path: String,
    /// Base entry (common ancestor).
    pub base: Option<TreeEntry>,
    /// Our entry.
    pub ours: Option<TreeEntry>,
    /// Their entry.
    pub theirs: Option<TreeEntry>,
    /// Conflict type.
    pub conflict_type: ConflictType,
}

/// Conflict type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictType {
    /// Both sides modified differently.
    BothModified,
    /// We deleted, they modified.
    DeleteModify,
    /// We modified, they deleted.
    ModifyDelete,
    /// Both added different content.
    BothAdded,
    /// Type conflict (e.g., file vs directory).
    TypeConflict,
}

impl MergeResult {
    /// Creates a clean merge.
    pub fn clean(tree: Tree) -> Self {
        Self {
            tree: Some(tree),
            conflicts: Vec::new(),
            clean: true,
        }
    }

    /// Creates a conflicted merge.
    pub fn conflicted(conflicts: Vec<MergeConflict>) -> Self {
        Self {
            tree: None,
            conflicts,
            clean: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_trees() -> (Tree, Tree) {
        let mut old = Tree::new();
        old.add(TreeEntry::blob("unchanged.txt", "hash1", 100));
        old.add(TreeEntry::blob("modified.txt", "hash2", 200));
        old.add(TreeEntry::blob("deleted.txt", "hash3", 300));
        old.add(TreeEntry::blob("renamed_old.txt", "hash4", 400));

        let mut new = Tree::new();
        new.add(TreeEntry::blob("unchanged.txt", "hash1", 100));
        new.add(TreeEntry::blob("modified.txt", "hash2_new", 250));
        new.add(TreeEntry::blob("added.txt", "hash5", 150));
        new.add(TreeEntry::blob("renamed_new.txt", "hash4", 400));

        (old, new)
    }

    #[test]
    fn test_diff_basic() {
        let (old, new) = create_test_trees();
        let diff = Diff::compute(&old, &new, &DiffOptions::default());

        assert!(!diff.is_empty());
        assert_eq!(diff.stats.added, 1);
        assert_eq!(diff.stats.deleted, 1);
        assert_eq!(diff.stats.modified, 1);
        assert_eq!(diff.stats.renamed, 1);
    }

    #[test]
    fn test_diff_no_renames() {
        let (old, new) = create_test_trees();
        let options = DiffOptions {
            detect_renames: false,
            ..Default::default()
        };
        let diff = Diff::compute(&old, &new, &options);

        // Without rename detection, renamed counts as add + delete
        assert_eq!(diff.stats.renamed, 0);
        assert_eq!(diff.stats.added, 2);
        assert_eq!(diff.stats.deleted, 2);
    }

    #[test]
    fn test_diff_empty() {
        let tree = Tree::new();
        let diff = Diff::compute(&tree, &tree, &DiffOptions::default());

        assert!(diff.is_empty());
    }

    #[test]
    fn test_diff_entry_size_change() {
        let old_entry = TreeEntry::blob("file.txt", "old", 100);
        let new_entry = TreeEntry::blob("file.txt", "new", 150);

        let diff_entry = DiffEntry::modified("file.txt", old_entry, new_entry);

        assert_eq!(diff_entry.size_change(), 50);
    }

    #[test]
    fn test_diff_stats() {
        let (old, new) = create_test_trees();
        let diff = Diff::compute(&old, &new, &DiffOptions::default());

        assert!(diff.stats.insertions > 0);
        assert!(diff.stats.deletions > 0);
    }
}
