//! Storage backend integration tests.

use vault_storage::{InMemoryBackend, FilesystemBackend, StorageBackend};
use std::sync::Arc;
use tempfile::TempDir;

/// Tests in-memory backend basic operations.
#[tokio::test]
async fn test_memory_backend_basic() {
    let backend = InMemoryBackend::new();

    let key = "test-key";
    let value = b"test value";

    // Put
    backend.put(key, value).await.unwrap();

    // Get
    let retrieved = backend.get(key).await.unwrap();
    assert_eq!(retrieved, value);

    // Exists
    assert!(backend.exists(key).await.unwrap());

    // Delete
    backend.delete(key).await.unwrap();
    assert!(!backend.exists(key).await.unwrap());
}

/// Tests in-memory backend handles missing keys.
#[tokio::test]
async fn test_memory_backend_missing_key() {
    let backend = InMemoryBackend::new();

    let result = backend.get("nonexistent").await;
    assert!(result.is_err());
}

/// Tests in-memory backend list operation.
#[tokio::test]
async fn test_memory_backend_list() {
    let backend = InMemoryBackend::new();

    // Store some items
    backend.put("key1", b"value1").await.unwrap();
    backend.put("key2", b"value2").await.unwrap();
    backend.put("key3", b"value3").await.unwrap();

    // List all
    let keys = backend.list(None).await.unwrap();
    assert_eq!(keys.len(), 3);
    assert!(keys.contains(&"key1".to_string()));
    assert!(keys.contains(&"key2".to_string()));
    assert!(keys.contains(&"key3".to_string()));
}

/// Tests in-memory backend list with prefix.
#[tokio::test]
async fn test_memory_backend_list_prefix() {
    let backend = InMemoryBackend::new();

    backend.put("data/file1", b"value1").await.unwrap();
    backend.put("data/file2", b"value2").await.unwrap();
    backend.put("other/file", b"value3").await.unwrap();

    // List with prefix
    let keys = backend.list(Some("data/")).await.unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| k.starts_with("data/")));
}

/// Tests in-memory backend statistics.
#[tokio::test]
async fn test_memory_backend_stats() {
    let backend = InMemoryBackend::new();

    backend.put("key1", b"short").await.unwrap();
    backend.put("key2", b"longer value here").await.unwrap();

    let stats = backend.stats();
    assert_eq!(stats.object_count, 2);
    assert!(stats.total_size > 0);
}

/// Tests in-memory backend concurrent access.
#[tokio::test]
async fn test_memory_backend_concurrent() {
    let backend = Arc::new(InMemoryBackend::new());

    let mut handles = vec![];

    for i in 0..100 {
        let backend = backend.clone();
        handles.push(tokio::spawn(async move {
            let key = format!("key-{}", i);
            let value = format!("value-{}", i);
            backend.put(&key, value.as_bytes()).await
        }));
    }

    for handle in handles {
        handle.await.expect("Task panicked").expect("Put failed");
    }

    let stats = backend.stats();
    assert_eq!(stats.object_count, 100);
}

/// Tests filesystem backend basic operations.
#[tokio::test]
async fn test_filesystem_backend_basic() {
    let temp_dir = TempDir::new().unwrap();
    let backend = FilesystemBackend::new(temp_dir.path()).await.unwrap();

    let key = "test-key";
    let value = b"test value";

    // Put
    backend.put(key, value).await.unwrap();

    // Get
    let retrieved = backend.get(key).await.unwrap();
    assert_eq!(retrieved, value);

    // Exists
    assert!(backend.exists(key).await.unwrap());

    // Delete
    backend.delete(key).await.unwrap();
    assert!(!backend.exists(key).await.unwrap());
}

/// Tests filesystem backend handles nested keys.
#[tokio::test]
async fn test_filesystem_backend_nested_keys() {
    let temp_dir = TempDir::new().unwrap();
    let backend = FilesystemBackend::new(temp_dir.path()).await.unwrap();

    let key = "path/to/nested/file";
    let value = b"nested content";

    backend.put(key, value).await.unwrap();

    let retrieved = backend.get(key).await.unwrap();
    assert_eq!(retrieved, value);
}

/// Tests filesystem backend handles large files.
#[tokio::test]
async fn test_filesystem_backend_large_file() {
    let temp_dir = TempDir::new().unwrap();
    let backend = FilesystemBackend::new(temp_dir.path()).await.unwrap();

    // 10MB file
    let value: Vec<u8> = (0..10 * 1024 * 1024).map(|i| (i % 256) as u8).collect();

    backend.put("large-file", &value).await.unwrap();

    let retrieved = backend.get("large-file").await.unwrap();
    assert_eq!(retrieved.len(), value.len());
    assert_eq!(retrieved, value);
}

/// Tests filesystem backend handles binary data.
#[tokio::test]
async fn test_filesystem_backend_binary() {
    let temp_dir = TempDir::new().unwrap();
    let backend = FilesystemBackend::new(temp_dir.path()).await.unwrap();

    let value: Vec<u8> = vec![0, 1, 2, 0, 255, 254, 0, 128];

    backend.put("binary", &value).await.unwrap();

    let retrieved = backend.get("binary").await.unwrap();
    assert_eq!(retrieved, value);
}

/// Tests filesystem backend list operation.
#[tokio::test]
async fn test_filesystem_backend_list() {
    let temp_dir = TempDir::new().unwrap();
    let backend = FilesystemBackend::new(temp_dir.path()).await.unwrap();

    backend.put("file1", b"content1").await.unwrap();
    backend.put("file2", b"content2").await.unwrap();
    backend.put("dir/file3", b"content3").await.unwrap();

    let keys = backend.list(None).await.unwrap();
    assert!(keys.len() >= 3);
}

/// Tests filesystem backend handles special characters in keys.
#[tokio::test]
async fn test_filesystem_backend_special_chars() {
    let temp_dir = TempDir::new().unwrap();
    let backend = FilesystemBackend::new(temp_dir.path()).await.unwrap();

    // Keys with special characters (but filesystem-safe)
    let keys = vec![
        "file-with-dashes",
        "file_with_underscores",
        "file.with.dots",
        "path/to/file",
    ];

    for key in keys {
        backend.put(key, b"value").await.unwrap();
        assert!(backend.exists(key).await.unwrap());
    }
}

/// Tests filesystem backend handles empty files.
#[tokio::test]
async fn test_filesystem_backend_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let backend = FilesystemBackend::new(temp_dir.path()).await.unwrap();

    backend.put("empty", b"").await.unwrap();

    let retrieved = backend.get("empty").await.unwrap();
    assert!(retrieved.is_empty());
}

/// Tests filesystem backend handles missing directory.
#[tokio::test]
async fn test_filesystem_backend_missing_dir() {
    let temp_dir = TempDir::new().unwrap();
    let missing_path = temp_dir.path().join("nonexistent");

    // Should create the directory
    let result = FilesystemBackend::new(&missing_path).await;
    assert!(result.is_ok());
}

/// Tests filesystem backend concurrent writes.
#[tokio::test]
async fn test_filesystem_backend_concurrent_writes() {
    let temp_dir = TempDir::new().unwrap();
    let backend = Arc::new(FilesystemBackend::new(temp_dir.path()).await.unwrap());

    let mut handles = vec![];

    for i in 0..50 {
        let backend = backend.clone();
        handles.push(tokio::spawn(async move {
            let key = format!("concurrent-{}", i);
            let value = format!("value-{}", i);
            backend.put(&key, value.as_bytes()).await
        }));
    }

    for handle in handles {
        handle.await.expect("Task panicked").expect("Put failed");
    }

    // Verify all files were written
    for i in 0..50 {
        let key = format!("concurrent-{}", i);
        assert!(backend.exists(&key).await.unwrap());
    }
}

/// Tests storage backend trait is object-safe.
#[tokio::test]
async fn test_backend_trait_object_safe() {
    let memory: Box<dyn StorageBackend> = Box::new(InMemoryBackend::new());

    memory.put("key", b"value").await.unwrap();
    let retrieved = memory.get("key").await.unwrap();
    assert_eq!(retrieved, b"value");
}

/// Tests switching between backends.
#[tokio::test]
async fn test_backend_migration() {
    // Start with memory backend
    let memory = InMemoryBackend::new();

    memory.put("key1", b"value1").await.unwrap();
    memory.put("key2", b"value2").await.unwrap();

    // Create filesystem backend
    let temp_dir = TempDir::new().unwrap();
    let filesystem = FilesystemBackend::new(temp_dir.path()).await.unwrap();

    // Copy data
    let keys = memory.list(None).await.unwrap();
    for key in keys {
        let value = memory.get(&key).await.unwrap();
        filesystem.put(&key, &value).await.unwrap();
    }

    // Verify data in filesystem backend
    assert!(filesystem.exists("key1").await.unwrap());
    assert!(filesystem.exists("key2").await.unwrap());
    assert_eq!(filesystem.get("key1").await.unwrap(), b"value1");
    assert_eq!(filesystem.get("key2").await.unwrap(), b"value2");
}
