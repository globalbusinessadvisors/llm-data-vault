# Vault SDK

Official Rust SDK for LLM Data Vault - enterprise-grade client library for secure storage and anonymization of LLM training data.

## Features

- **Type-safe API client** - Fully typed request/response models
- **Async-first design** - Built on tokio for high performance
- **Automatic retries** - Configurable exponential backoff for transient failures
- **Connection pooling** - Efficient HTTP connection reuse
- **Multiple auth methods** - API key and JWT token support
- **Streaming support** - Stream large datasets efficiently
- **Comprehensive error handling** - Detailed, actionable error types

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
vault-sdk = "0.1"
```

## Quick Start

```rust
use vault_sdk::{VaultClient, DatasetCreate, DatasetFormat};

#[tokio::main]
async fn main() -> Result<(), vault_sdk::Error> {
    // Create client with API key
    let client = VaultClient::builder()
        .base_url("https://vault.example.com")
        .api_key("your-api-key")
        .build()?;

    // Create a dataset
    let dataset = client.datasets().create(
        &DatasetCreate::new("Training Data")
            .with_description("Q4 fine-tuning dataset")
            .with_format(DatasetFormat::Jsonl)
    ).await?;

    println!("Created dataset: {}", dataset.id);

    // Add records
    let record = client.records(&dataset.id.to_string())
        .create(&RecordCreate::json(serde_json::json!({
            "prompt": "What is machine learning?",
            "response": "Machine learning is..."
        })))
        .await?;

    // Detect PII
    let result = client.pii()
        .detect("Contact john@example.com for help")
        .await?;

    for entity in result.entities {
        println!("Found {}: {}", entity.pii_type, entity.text);
    }

    Ok(())
}
```

## Authentication

### API Key

```rust
let client = VaultClient::builder()
    .base_url("https://vault.example.com")
    .api_key("vk_live_xxxxx")
    .build()?;
```

### Bearer Token

```rust
let client = VaultClient::builder()
    .base_url("https://vault.example.com")
    .bearer_token("eyJ...")
    .build()?;
```

## Configuration

```rust
use std::time::Duration;

let client = VaultClient::builder()
    .base_url("https://vault.example.com")
    .api_key("your-key")
    .timeout(Duration::from_secs(60))
    .connect_timeout(Duration::from_secs(10))
    .max_retries(5)
    .build()?;
```

## Error Handling

```rust
match client.datasets().get("ds_123").await {
    Ok(dataset) => println!("Found: {}", dataset.name),
    Err(vault_sdk::Error::NotFound { .. }) => println!("Dataset not found"),
    Err(vault_sdk::Error::Unauthorized { .. }) => println!("Invalid credentials"),
    Err(vault_sdk::Error::RateLimited { retry_after_secs }) => {
        println!("Rate limited, retry after {} seconds", retry_after_secs);
    }
    Err(e) if e.is_retryable() => println!("Transient error: {}", e),
    Err(e) => eprintln!("Error: {}", e),
}
```

## Services

### Datasets

```rust
// List datasets
let datasets = client.datasets().list().await?;

// Create dataset
let dataset = client.datasets().create(&DatasetCreate::new("Name")).await?;

// Get dataset
let dataset = client.datasets().get("ds_123").await?;

// Update dataset
let dataset = client.datasets().update("ds_123", &DatasetUpdate::new()
    .with_name("New Name")
).await?;

// Delete dataset
client.datasets().delete("ds_123").await?;

// Get statistics
let stats = client.datasets().stats("ds_123").await?;
```

### Records

```rust
let records = client.records("ds_123");

// List records
let list = records.list().await?;

// Create record
let record = records.create(&RecordCreate::json(json!({...}))).await?;

// Bulk create
let result = records.create_bulk(&BulkRecordCreate {
    records: vec![...],
    continue_on_error: true,
}).await?;

// Get PII results
let pii = records.pii_results("rec_456").await?;
```

### PII Detection & Anonymization

```rust
// Detect PII
let result = client.pii().detect("Text with john@example.com").await?;

// Anonymize
let result = client.pii().anonymize("Text with john@example.com").await?;
println!("Anonymized: {}", result.anonymized_text);
// Output: "Text with [EMAIL]"

// Check if clean
if client.pii().is_clean("Some text").await? {
    println!("No PII detected");
}
```

### Webhooks

```rust
// Create webhook
let webhook = client.webhooks().create(&WebhookCreate::new(
    "Record Events",
    "https://api.example.com/webhook",
    vec![WebhookEvent::RecordCreated, WebhookEvent::PiiDetected],
)).await?;

// Test webhook
let delivery = client.webhooks().test(&webhook.id.to_string()).await?;

// List deliveries
let deliveries = client.webhooks().deliveries(&webhook.id.to_string()).await?;
```

## License

MIT
