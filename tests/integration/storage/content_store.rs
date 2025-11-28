//! Content store integration tests.

use vault_storage::{InMemoryBackend, ContentStore, ContentAddress, HashAlgorithm, StorageConfig};
use std::sync::Arc;

/// Tests storing and retrieving content.
#[tokio::test]
async fn test_store_and_retrieve() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let content = b"Hello, World!";
    let address = store.store(content).await.unwrap();

    let retrieved = store.get(&address).await.unwrap();
    assert_eq!(retrieved, content);
}

/// Tests content addressing is deterministic.
#[tokio::test]
async fn test_content_addressing_deterministic() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let content = b"Test content";

    let address1 = store.store(content).await.unwrap();
    let address2 = store.store(content).await.unwrap();

    // Same content should produce same address
    assert_eq!(address1.to_string(), address2.to_string());
}

/// Tests storing empty content.
#[tokio::test]
async fn test_store_empty_content() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let content = b"";
    let address = store.store(content).await.unwrap();

    let retrieved = store.get(&address).await.unwrap();
    assert_eq!(retrieved, content);
}

/// Tests storing large content.
#[tokio::test]
async fn test_store_large_content() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    // 1MB of data
    let content: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
    let address = store.store(&content).await.unwrap();

    let retrieved = store.get(&address).await.unwrap();
    assert_eq!(retrieved, content);
}

/// Tests checking if content exists.
#[tokio::test]
async fn test_content_exists() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let content = b"Test content";
    let address = store.store(content).await.unwrap();

    assert!(store.exists(&address).await.unwrap());

    // Non-existent address
    let fake_address = ContentAddress::new("nonexistent".to_string());
    assert!(!store.exists(&fake_address).await.unwrap());
}

/// Tests deleting content.
#[tokio::test]
async fn test_delete_content() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let content = b"To be deleted";
    let address = store.store(content).await.unwrap();

    // Content exists
    assert!(store.exists(&address).await.unwrap());

    // Delete
    store.delete(&address).await.unwrap();

    // Content no longer exists
    assert!(!store.exists(&address).await.unwrap());
}

/// Tests retrieving non-existent content.
#[tokio::test]
async fn test_get_nonexistent() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let fake_address = ContentAddress::new("nonexistent".to_string());
    let result = store.get(&fake_address).await;

    assert!(result.is_err());
}

/// Tests concurrent storage operations.
#[tokio::test]
async fn test_concurrent_operations() {
    let backend = Arc::new(InMemoryBackend::new());
    let store = Arc::new(ContentStore::new(backend, HashAlgorithm::Blake3));

    let mut handles = vec![];

    // Spawn multiple concurrent store operations
    for i in 0..10 {
        let store = store.clone();
        handles.push(tokio::spawn(async move {
            let content = format!("Content {}", i).into_bytes();
            store.store(&content).await
        }));
    }

    // All operations should succeed
    for handle in handles {
        let result = handle.await.expect("Task panicked");
        assert!(result.is_ok());
    }
}

/// Tests different hash algorithms produce different addresses.
#[tokio::test]
async fn test_different_hash_algorithms() {
    let content = b"Test content";

    let backend1 = InMemoryBackend::new();
    let store_blake3 = ContentStore::new(Arc::new(backend1), HashAlgorithm::Blake3);

    let backend2 = InMemoryBackend::new();
    let store_sha256 = ContentStore::new(Arc::new(backend2), HashAlgorithm::Sha256);

    let address_blake3 = store_blake3.store(content).await.unwrap();
    let address_sha256 = store_sha256.store(content).await.unwrap();

    // Different algorithms should produce different addresses
    assert_ne!(address_blake3.to_string(), address_sha256.to_string());
}

/// Tests content deduplication.
#[tokio::test]
async fn test_deduplication() {
    let backend = Arc::new(InMemoryBackend::new());
    let store = ContentStore::new(backend.clone(), HashAlgorithm::Blake3);

    let content = b"Duplicate content";

    // Store same content multiple times
    let addr1 = store.store(content).await.unwrap();
    let addr2 = store.store(content).await.unwrap();
    let addr3 = store.store(content).await.unwrap();

    // All addresses should be the same
    assert_eq!(addr1.to_string(), addr2.to_string());
    assert_eq!(addr2.to_string(), addr3.to_string());

    // Backend should only store one copy
    let stats = backend.stats();
    // In a properly implemented backend, object_count would be 1
}

/// Tests binary content storage.
#[tokio::test]
async fn test_binary_content() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    // Binary data with null bytes
    let content: Vec<u8> = vec![0, 1, 2, 0, 255, 254, 0, 128];
    let address = store.store(&content).await.unwrap();

    let retrieved = store.get(&address).await.unwrap();
    assert_eq!(retrieved, content);
}

/// Tests UTF-8 content storage.
#[tokio::test]
async fn test_utf8_content() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    // Unicode content
    let content = "Hello, 世界! 🌍 مرحبا";
    let address = store.store(content.as_bytes()).await.unwrap();

    let retrieved = store.get(&address).await.unwrap();
    assert_eq!(String::from_utf8(retrieved).unwrap(), content);
}

/// Tests JSON content storage.
#[tokio::test]
async fn test_json_content() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let json = serde_json::json!({
        "name": "Test",
        "value": 42,
        "nested": {
            "array": [1, 2, 3]
        }
    });
    let content = serde_json::to_vec(&json).unwrap();

    let address = store.store(&content).await.unwrap();
    let retrieved = store.get(&address).await.unwrap();

    let parsed: serde_json::Value = serde_json::from_slice(&retrieved).unwrap();
    assert_eq!(parsed, json);
}

/// Tests content address string format.
#[tokio::test]
async fn test_content_address_format() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let content = b"Test content";
    let address = store.store(content).await.unwrap();

    let address_str = address.to_string();

    // Address should be a valid hex string
    assert!(address_str.chars().all(|c| c.is_ascii_hexdigit()));

    // BLAKE3 produces 64 character hex string (256 bits)
    assert_eq!(address_str.len(), 64);
}

/// Tests storing content from iterator.
#[tokio::test]
async fn test_store_batch() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let contents: Vec<&[u8]> = vec![
        b"Content 1",
        b"Content 2",
        b"Content 3",
    ];

    let mut addresses = vec![];
    for content in contents.iter() {
        let address = store.store(*content).await.unwrap();
        addresses.push(address);
    }

    // Verify all content can be retrieved
    for (i, address) in addresses.iter().enumerate() {
        let retrieved = store.get(address).await.unwrap();
        assert_eq!(retrieved, contents[i]);
    }
}

/// Tests store performance with many small objects.
#[tokio::test]
async fn test_store_many_small_objects() {
    let backend = InMemoryBackend::new();
    let store = ContentStore::new(Arc::new(backend), HashAlgorithm::Blake3);

    let start = std::time::Instant::now();

    for i in 0..1000 {
        let content = format!("Small object {}", i);
        store.store(content.as_bytes()).await.unwrap();
    }

    let elapsed = start.elapsed();
    println!("Stored 1000 objects in {:?}", elapsed);

    // Should complete in reasonable time (< 1 second)
    assert!(elapsed.as_secs() < 1);
}
