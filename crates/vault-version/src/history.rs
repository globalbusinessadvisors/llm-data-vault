//! Commit history queries and traversal.

use crate::{Commit, CommitId, VersionError, VersionResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// A history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Commit.
    pub commit: Commit,
    /// Depth from starting point.
    pub depth: usize,
    /// Is on main/first-parent line.
    pub is_first_parent: bool,
    /// Branch name (if known).
    pub branch: Option<String>,
}

impl HistoryEntry {
    /// Creates a new history entry.
    pub fn new(commit: Commit, depth: usize, is_first_parent: bool) -> Self {
        Self {
            commit,
            depth,
            is_first_parent,
            branch: None,
        }
    }

    /// Sets the branch name.
    #[must_use]
    pub fn with_branch(mut self, branch: impl Into<String>) -> Self {
        self.branch = Some(branch.into());
        self
    }
}

/// History query options.
#[derive(Debug, Clone)]
pub struct HistoryQuery {
    /// Starting commit(s).
    pub from: Vec<CommitId>,
    /// Ending commit(s) - stop traversal here.
    pub until: Vec<CommitId>,
    /// Maximum number of commits.
    pub limit: Option<usize>,
    /// Skip first N commits.
    pub skip: usize,
    /// Only follow first parent (linear history).
    pub first_parent_only: bool,
    /// Filter by author.
    pub author: Option<String>,
    /// Filter by message pattern.
    pub message_pattern: Option<String>,
    /// Filter by time range (since).
    pub since: Option<DateTime<Utc>>,
    /// Filter by time range (until).
    pub before: Option<DateTime<Utc>>,
    /// Filter by path (commits touching this path).
    pub path: Option<String>,
    /// Include merge commits.
    pub include_merges: bool,
    /// Sort order.
    pub sort: HistorySort,
}

/// History sort order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HistorySort {
    /// Topological order (default).
    #[default]
    Topological,
    /// Chronological (oldest first).
    Chronological,
    /// Reverse chronological (newest first).
    ReverseChronological,
}

impl Default for HistoryQuery {
    fn default() -> Self {
        Self {
            from: Vec::new(),
            until: Vec::new(),
            limit: None,
            skip: 0,
            first_parent_only: false,
            author: None,
            message_pattern: None,
            since: None,
            before: None,
            path: None,
            include_merges: true,
            sort: HistorySort::default(),
        }
    }
}

impl HistoryQuery {
    /// Creates a new query starting from a commit.
    pub fn from(commit: CommitId) -> Self {
        Self {
            from: vec![commit],
            ..Default::default()
        }
    }

    /// Adds another starting point.
    #[must_use]
    pub fn and_from(mut self, commit: CommitId) -> Self {
        self.from.push(commit);
        self
    }

    /// Sets the stopping point.
    #[must_use]
    pub fn until(mut self, commit: CommitId) -> Self {
        self.until.push(commit);
        self
    }

    /// Sets the limit.
    #[must_use]
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Sets the skip count.
    #[must_use]
    pub fn skip(mut self, n: usize) -> Self {
        self.skip = n;
        self
    }

    /// Only follow first parent.
    #[must_use]
    pub fn first_parent(mut self) -> Self {
        self.first_parent_only = true;
        self
    }

    /// Filters by author.
    #[must_use]
    pub fn by_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Filters by message pattern.
    #[must_use]
    pub fn message_contains(mut self, pattern: impl Into<String>) -> Self {
        self.message_pattern = Some(pattern.into());
        self
    }

    /// Filters by time range.
    #[must_use]
    pub fn time_range(mut self, since: DateTime<Utc>, before: DateTime<Utc>) -> Self {
        self.since = Some(since);
        self.before = Some(before);
        self
    }

    /// Filters by path.
    #[must_use]
    pub fn touching_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Excludes merge commits.
    #[must_use]
    pub fn no_merges(mut self) -> Self {
        self.include_merges = false;
        self
    }

    /// Sets sort order.
    #[must_use]
    pub fn sort_by(mut self, sort: HistorySort) -> Self {
        self.sort = sort;
        self
    }
}

/// History traversal and queries.
pub struct History {
    /// Commits by ID.
    commits: HashMap<String, Commit>,
    /// Children map (reverse of parent relationships).
    children: HashMap<String, Vec<CommitId>>,
}

impl History {
    /// Creates a new history store.
    pub fn new() -> Self {
        Self {
            commits: HashMap::new(),
            children: HashMap::new(),
        }
    }

    /// Adds a commit to the history.
    pub fn add_commit(&mut self, commit: Commit) {
        if let Some(id) = commit.id() {
            // Update children map
            for parent in &commit.parents {
                self.children
                    .entry(parent.as_str().to_string())
                    .or_default()
                    .push(id.clone());
            }

            self.commits.insert(id.as_str().to_string(), commit);
        }
    }

    /// Gets a commit by ID.
    pub fn get(&self, id: &CommitId) -> Option<&Commit> {
        self.commits.get(id.as_str())
    }

    /// Gets commit children.
    pub fn children_of(&self, id: &CommitId) -> Vec<&Commit> {
        self.children
            .get(id.as_str())
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.commits.get(id.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Executes a history query.
    pub fn query(&self, query: &HistoryQuery) -> Vec<HistoryEntry> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        // Convert until commits to set for fast lookup
        let stop_at: HashSet<&str> = query.until.iter().map(|c| c.as_str()).collect();

        // Initialize queue with starting commits
        for start in &query.from {
            if let Some(commit) = self.commits.get(start.as_str()) {
                queue.push_back((commit, 0usize, true));
            }
        }

        let mut skipped = 0;

        while let Some((commit, depth, is_first_parent)) = queue.pop_front() {
            let commit_id = match commit.id() {
                Some(id) => id.as_str().to_string(),
                None => continue,
            };

            // Skip if already visited
            if !visited.insert(commit_id.clone()) {
                continue;
            }

            // Stop at boundary
            if stop_at.contains(commit_id.as_str()) {
                continue;
            }

            // Apply filters
            if !self.matches_filters(commit, query) {
                // Still traverse parents even if commit doesn't match
                self.enqueue_parents(commit, depth, query, &mut queue);
                continue;
            }

            // Handle skip
            if skipped < query.skip {
                skipped += 1;
                self.enqueue_parents(commit, depth, query, &mut queue);
                continue;
            }

            // Add to result
            result.push(HistoryEntry::new(commit.clone(), depth, is_first_parent));

            // Check limit
            if let Some(limit) = query.limit {
                if result.len() >= limit {
                    break;
                }
            }

            // Enqueue parents
            self.enqueue_parents(commit, depth, query, &mut queue);
        }

        // Sort results
        match query.sort {
            HistorySort::Topological => {
                // Already in topological order from BFS
            }
            HistorySort::Chronological => {
                result.sort_by(|a, b| a.commit.timestamp.cmp(&b.commit.timestamp));
            }
            HistorySort::ReverseChronological => {
                result.sort_by(|a, b| b.commit.timestamp.cmp(&a.commit.timestamp));
            }
        }

        result
    }

    fn matches_filters(&self, commit: &Commit, query: &HistoryQuery) -> bool {
        // Filter merges
        if !query.include_merges && commit.is_merge() {
            return false;
        }

        // Filter by author
        if let Some(ref author) = query.author {
            if !commit.author.name.contains(author) && !commit.author.email.contains(author) {
                return false;
            }
        }

        // Filter by message
        if let Some(ref pattern) = query.message_pattern {
            if !commit.message.contains(pattern) {
                return false;
            }
        }

        // Filter by time range
        if let Some(since) = query.since {
            if commit.timestamp < since {
                return false;
            }
        }
        if let Some(before) = query.before {
            if commit.timestamp > before {
                return false;
            }
        }

        true
    }

    fn enqueue_parents<'a>(
        &'a self,
        commit: &Commit,
        depth: usize,
        query: &HistoryQuery,
        queue: &mut VecDeque<(&'a Commit, usize, bool)>,
    ) {
        if query.first_parent_only {
            // Only follow first parent
            if let Some(parent_id) = commit.parent() {
                if let Some(parent) = self.commits.get(parent_id.as_str()) {
                    queue.push_back((parent, depth + 1, true));
                }
            }
        } else {
            // Follow all parents
            for (i, parent_id) in commit.parents.iter().enumerate() {
                if let Some(parent) = self.commits.get(parent_id.as_str()) {
                    queue.push_back((parent, depth + 1, i == 0));
                }
            }
        }
    }

    /// Finds the merge base (common ancestor) of two commits.
    pub fn merge_base(&self, a: &CommitId, b: &CommitId) -> Option<CommitId> {
        // Get all ancestors of a
        let ancestors_a = self.ancestors(a);

        // BFS from b, first ancestor in ancestors_a is merge base
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(b.clone());

        while let Some(current) = queue.pop_front() {
            if ancestors_a.contains(current.as_str()) {
                return Some(current);
            }

            if visited.insert(current.as_str().to_string()) {
                if let Some(commit) = self.commits.get(current.as_str()) {
                    for parent in &commit.parents {
                        queue.push_back(parent.clone());
                    }
                }
            }
        }

        None
    }

    /// Gets all ancestors of a commit.
    fn ancestors(&self, id: &CommitId) -> HashSet<String> {
        let mut ancestors = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(id.clone());

        while let Some(current) = queue.pop_front() {
            if ancestors.insert(current.as_str().to_string()) {
                if let Some(commit) = self.commits.get(current.as_str()) {
                    for parent in &commit.parents {
                        queue.push_back(parent.clone());
                    }
                }
            }
        }

        ancestors
    }

    /// Checks if a commit is an ancestor of another.
    pub fn is_ancestor(&self, potential_ancestor: &CommitId, descendant: &CommitId) -> bool {
        if potential_ancestor == descendant {
            return true;
        }

        let ancestors = self.ancestors(descendant);
        ancestors.contains(potential_ancestor.as_str())
    }

    /// Gets the commit count between two commits.
    pub fn commit_count(&self, from: &CommitId, to: &CommitId) -> usize {
        let query = HistoryQuery::from(to.clone()).until(from.clone());
        self.query(&query).len()
    }

    /// Gets commits between two dates.
    pub fn commits_between(
        &self,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Vec<&Commit> {
        self.commits
            .values()
            .filter(|c| c.timestamp >= since && c.timestamp <= until)
            .collect()
    }

    /// Gets commits by author.
    pub fn commits_by_author(&self, author: &str) -> Vec<&Commit> {
        self.commits
            .values()
            .filter(|c| c.author.name.contains(author) || c.author.email.contains(author))
            .collect()
    }

    /// Returns statistics about the history.
    pub fn stats(&self) -> HistoryStats {
        let commits: Vec<&Commit> = self.commits.values().collect();

        let mut authors: HashMap<String, usize> = HashMap::new();
        let mut merge_commits = 0;

        for commit in &commits {
            *authors.entry(commit.author.email.clone()).or_default() += 1;
            if commit.is_merge() {
                merge_commits += 1;
            }
        }

        let first_commit = commits.iter().min_by_key(|c| c.timestamp);
        let last_commit = commits.iter().max_by_key(|c| c.timestamp);

        HistoryStats {
            total_commits: commits.len(),
            merge_commits,
            author_count: authors.len(),
            top_authors: {
                let mut sorted: Vec<_> = authors.into_iter().collect();
                sorted.sort_by(|a, b| b.1.cmp(&a.1));
                sorted.into_iter().take(10).collect()
            },
            first_commit_date: first_commit.map(|c| c.timestamp),
            last_commit_date: last_commit.map(|c| c.timestamp),
        }
    }

    /// Gets all root commits (commits with no parents).
    pub fn roots(&self) -> Vec<&Commit> {
        self.commits
            .values()
            .filter(|c| c.is_root())
            .collect()
    }

    /// Gets all leaf commits (commits with no children).
    pub fn leaves(&self) -> Vec<&Commit> {
        self.commits
            .values()
            .filter(|c| {
                c.id()
                    .map(|id| !self.children.contains_key(id.as_str()))
                    .unwrap_or(true)
            })
            .collect()
    }

    /// Returns the total number of commits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.commits.len()
    }

    /// Returns true if history is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commits.is_empty()
    }
}

impl Default for History {
    fn default() -> Self {
        Self::new()
    }
}

/// History statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryStats {
    /// Total number of commits.
    pub total_commits: usize,
    /// Number of merge commits.
    pub merge_commits: usize,
    /// Number of unique authors.
    pub author_count: usize,
    /// Top authors by commit count.
    pub top_authors: Vec<(String, usize)>,
    /// First commit date.
    pub first_commit_date: Option<DateTime<Utc>>,
    /// Last commit date.
    pub last_commit_date: Option<DateTime<Utc>>,
}

/// Blame information for a line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameEntry {
    /// Commit that last modified this line.
    pub commit_id: CommitId,
    /// Author who made the change.
    pub author: String,
    /// Timestamp of the change.
    pub timestamp: DateTime<Utc>,
    /// Line number.
    pub line_number: usize,
    /// Line content.
    pub content: String,
}

/// Blame result for a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameResult {
    /// Path of the file.
    pub path: String,
    /// Blame entries per line.
    pub entries: Vec<BlameEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Author, CommitBuilder};

    fn create_test_commits() -> Vec<Commit> {
        let author = Author::new("Test", "test@example.com");

        // Create a simple linear history: c1 <- c2 <- c3
        let c1 = CommitBuilder::new()
            .tree("tree1")
            .author(author.clone())
            .message("First commit")
            .dataset("ds-1")
            .build()
            .unwrap();

        let c2 = CommitBuilder::new()
            .tree("tree2")
            .parent(c1.id().unwrap().clone())
            .author(author.clone())
            .message("Second commit")
            .dataset("ds-1")
            .build()
            .unwrap();

        let c3 = CommitBuilder::new()
            .tree("tree3")
            .parent(c2.id().unwrap().clone())
            .author(author)
            .message("Third commit")
            .dataset("ds-1")
            .build()
            .unwrap();

        vec![c1, c2, c3]
    }

    #[test]
    fn test_add_and_get_commits() {
        let mut history = History::new();
        let commits = create_test_commits();

        for commit in &commits {
            history.add_commit(commit.clone());
        }

        assert_eq!(history.len(), 3);

        let c1 = history.get(commits[0].id().unwrap());
        assert!(c1.is_some());
    }

    #[test]
    fn test_history_query() {
        let mut history = History::new();
        let commits = create_test_commits();

        for commit in &commits {
            history.add_commit(commit.clone());
        }

        // Query from c3
        let query = HistoryQuery::from(commits[2].id().unwrap().clone());
        let result = history.query(&query);

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_query_with_limit() {
        let mut history = History::new();
        let commits = create_test_commits();

        for commit in &commits {
            history.add_commit(commit.clone());
        }

        let query = HistoryQuery::from(commits[2].id().unwrap().clone()).limit(2);
        let result = history.query(&query);

        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_is_ancestor() {
        let mut history = History::new();
        let commits = create_test_commits();

        for commit in &commits {
            history.add_commit(commit.clone());
        }

        let c1_id = commits[0].id().unwrap();
        let c3_id = commits[2].id().unwrap();

        assert!(history.is_ancestor(c1_id, c3_id));
        assert!(!history.is_ancestor(c3_id, c1_id));
    }

    #[test]
    fn test_merge_base() {
        let mut history = History::new();
        let commits = create_test_commits();

        for commit in &commits {
            history.add_commit(commit.clone());
        }

        let c1_id = commits[0].id().unwrap();
        let c2_id = commits[1].id().unwrap();
        let c3_id = commits[2].id().unwrap();

        // Merge base of c2 and c3 should be c2
        let base = history.merge_base(c2_id, c3_id);
        assert_eq!(base, Some(c2_id.clone()));

        // Merge base of c1 and c3 should be c1
        let base = history.merge_base(c1_id, c3_id);
        assert_eq!(base, Some(c1_id.clone()));
    }

    #[test]
    fn test_roots_and_leaves() {
        let mut history = History::new();
        let commits = create_test_commits();

        for commit in &commits {
            history.add_commit(commit.clone());
        }

        let roots = history.roots();
        assert_eq!(roots.len(), 1);

        let leaves = history.leaves();
        assert_eq!(leaves.len(), 1);
    }

    #[test]
    fn test_stats() {
        let mut history = History::new();
        let commits = create_test_commits();

        for commit in &commits {
            history.add_commit(commit.clone());
        }

        let stats = history.stats();

        assert_eq!(stats.total_commits, 3);
        assert_eq!(stats.merge_commits, 0);
        assert_eq!(stats.author_count, 1);
    }

    #[test]
    fn test_children() {
        let mut history = History::new();
        let commits = create_test_commits();

        for commit in &commits {
            history.add_commit(commit.clone());
        }

        let c1_id = commits[0].id().unwrap();
        let children = history.children_of(c1_id);

        assert_eq!(children.len(), 1);
        assert_eq!(children[0].id(), commits[1].id());
    }
}
