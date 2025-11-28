//! Filesystem storage backend.

use crate::{StorageError, StorageResult};
use super::{ObjectMetadata, StorageBackend, StorageStats};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Filesystem storage backend.
pub struct FilesystemBackend {
    root: PathBuf,
    create_dirs: bool,
}

impl FilesystemBackend {
    /// Creates a new filesystem backend.
    pub async fn new(root: impl AsRef<Path>) -> StorageResult<Self> {
        let root = root.as_ref().to_path_buf();

        // Create root directory if it doesn't exist
        if !root.exists() {
            fs::create_dir_all(&root).await?;
        }

        Ok(Self {
            root,
            create_dirs: true,
        })
    }

    /// Creates without auto-creating directories.
    pub fn with_root(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            create_dirs: false,
        }
    }

    /// Sets whether to auto-create directories.
    #[must_use]
    pub fn auto_create_dirs(mut self, create: bool) -> Self {
        self.create_dirs = create;
        self
    }

    /// Resolves a key to a file path.
    fn key_to_path(&self, key: &str) -> PathBuf {
        // Sanitize key to prevent path traversal
        let sanitized: String = key
            .chars()
            .map(|c| if c == '/' { std::path::MAIN_SEPARATOR } else { c })
            .filter(|c| !matches!(c, '.' if key.contains("..")))
            .collect();

        self.root.join(sanitized)
    }

    /// Reads metadata from sidecar file.
    async fn read_metadata(&self, path: &Path) -> Option<HashMap<String, String>> {
        let meta_path = path.with_extension("meta.json");
        if meta_path.exists() {
            if let Ok(content) = fs::read_to_string(&meta_path).await {
                return serde_json::from_str(&content).ok();
            }
        }
        None
    }

    /// Writes metadata to sidecar file.
    async fn write_metadata(
        &self,
        path: &Path,
        metadata: &HashMap<String, String>,
    ) -> StorageResult<()> {
        let meta_path = path.with_extension("meta.json");
        let content = serde_json::to_string(metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        fs::write(&meta_path, content).await?;
        Ok(())
    }

    /// Calculates directory size recursively.
    async fn dir_size(&self, path: &Path) -> StorageResult<u64> {
        let mut total = 0u64;

        if path.is_dir() {
            let mut entries = fs::read_dir(path).await?;
            while let Some(entry) = entries.next_entry().await? {
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    total += Box::pin(self.dir_size(&entry_path)).await?;
                } else {
                    total += entry.metadata().await?.len();
                }
            }
        }

        Ok(total)
    }

    /// Counts files in directory recursively.
    async fn file_count(&self, path: &Path) -> StorageResult<u64> {
        let mut count = 0u64;

        if path.is_dir() {
            let mut entries = fs::read_dir(path).await?;
            while let Some(entry) = entries.next_entry().await? {
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    count += Box::pin(self.file_count(&entry_path)).await?;
                } else if !entry_path.extension().map_or(false, |e| e == "meta") {
                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

#[async_trait]
impl StorageBackend for FilesystemBackend {
    fn name(&self) -> &str {
        "filesystem"
    }

    async fn put(&self, key: &str, data: Bytes) -> StorageResult<()> {
        let path = self.key_to_path(key);

        // Create parent directories if needed
        if self.create_dirs {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).await?;
            }
        }

        // Write data atomically (write to temp, then rename)
        let temp_path = path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(&data).await?;
        file.sync_all().await?;

        fs::rename(&temp_path, &path).await?;

        Ok(())
    }

    async fn get(&self, key: &str) -> StorageResult<Bytes> {
        let path = self.key_to_path(key);

        if !path.exists() {
            return Err(StorageError::NotFound(key.to_string()));
        }

        let mut file = fs::File::open(&path).await?;
        let metadata = file.metadata().await?;
        let mut buffer = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut buffer).await?;

        Ok(Bytes::from(buffer))
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let path = self.key_to_path(key);

        if path.exists() {
            fs::remove_file(&path).await?;
        }

        // Also remove metadata sidecar
        let meta_path = path.with_extension("meta.json");
        if meta_path.exists() {
            let _ = fs::remove_file(&meta_path).await;
        }

        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let path = self.key_to_path(key);
        Ok(path.exists())
    }

    async fn list(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let search_path = match prefix {
            Some(p) => self.key_to_path(p),
            None => self.root.clone(),
        };

        let mut keys = Vec::new();

        if !search_path.exists() {
            return Ok(keys);
        }

        // Walk directory
        let mut stack = vec![search_path];
        while let Some(current) = stack.pop() {
            if current.is_dir() {
                let mut entries = fs::read_dir(&current).await?;
                while let Some(entry) = entries.next_entry().await? {
                    let entry_path = entry.path();
                    if entry_path.is_dir() {
                        stack.push(entry_path);
                    } else if !entry_path
                        .extension()
                        .map_or(false, |e| e == "meta" || e == "tmp")
                    {
                        // Convert path back to key
                        if let Ok(rel_path) = entry_path.strip_prefix(&self.root) {
                            let key = rel_path
                                .to_string_lossy()
                                .replace(std::path::MAIN_SEPARATOR, "/");
                            keys.push(key);
                        }
                    }
                }
            }
        }

        keys.sort();
        Ok(keys)
    }

    async fn head(&self, key: &str) -> StorageResult<ObjectMetadata> {
        let path = self.key_to_path(key);

        if !path.exists() {
            return Err(StorageError::NotFound(key.to_string()));
        }

        let file_metadata = fs::metadata(&path).await?;
        let modified = file_metadata
            .modified()
            .map(chrono::DateTime::<chrono::Utc>::from)
            .unwrap_or_else(|_| chrono::Utc::now());

        // Read custom metadata from sidecar
        let custom_metadata = self.read_metadata(&path).await.unwrap_or_default();

        // Calculate checksum
        let data = fs::read(&path).await?;
        let etag = blake3::hash(&data).to_hex().to_string();

        Ok(ObjectMetadata {
            size: file_metadata.len(),
            content_type: mime_guess::from_path(&path)
                .first()
                .map(|m| m.to_string()),
            last_modified: modified,
            etag: Some(etag),
            metadata: custom_metadata,
        })
    }

    async fn stats(&self) -> StorageResult<StorageStats> {
        let total_size = self.dir_size(&self.root).await?;
        let object_count = self.file_count(&self.root).await?;

        // Get available space
        let available_space = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                // Use statvfs on Unix systems
                None // Simplified for cross-platform
            }
            #[cfg(not(unix))]
            {
                None
            }
        };

        Ok(StorageStats {
            object_count,
            total_size,
            available_space,
            custom: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_backend() -> (FilesystemBackend, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let backend = FilesystemBackend::new(temp_dir.path()).await.unwrap();
        (backend, temp_dir)
    }

    #[tokio::test]
    async fn test_put_get() {
        let (backend, _temp) = create_test_backend().await;
        let data = Bytes::from("test data");

        backend.put("test.txt", data.clone()).await.unwrap();
        let retrieved = backend.get("test.txt").await.unwrap();

        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn test_nested_keys() {
        let (backend, _temp) = create_test_backend().await;

        backend
            .put("dir1/dir2/file.txt", Bytes::from("nested"))
            .await
            .unwrap();
        let data = backend.get("dir1/dir2/file.txt").await.unwrap();

        assert_eq!(data, Bytes::from("nested"));
    }

    #[tokio::test]
    async fn test_list() {
        let (backend, _temp) = create_test_backend().await;

        backend.put("a/1.txt", Bytes::from("1")).await.unwrap();
        backend.put("a/2.txt", Bytes::from("2")).await.unwrap();
        backend.put("b/3.txt", Bytes::from("3")).await.unwrap();

        let all = backend.list(None).await.unwrap();
        assert_eq!(all.len(), 3);

        let a_only = backend.list(Some("a")).await.unwrap();
        assert_eq!(a_only.len(), 2);
    }

    #[tokio::test]
    async fn test_delete() {
        let (backend, _temp) = create_test_backend().await;

        backend.put("to_delete", Bytes::from("data")).await.unwrap();
        assert!(backend.exists("to_delete").await.unwrap());

        backend.delete("to_delete").await.unwrap();
        assert!(!backend.exists("to_delete").await.unwrap());
    }
}
