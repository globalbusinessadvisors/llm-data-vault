//! # LLM Data Vault SDK
//!
//! Official Rust SDK for interacting with LLM Data Vault - an enterprise-grade
//! secure storage and anonymization solution for LLM training data.
//!
//! ## Features
//!
//! - **Type-safe API client** - Fully typed request/response models
//! - **Async-first design** - Built on tokio for high performance
//! - **Automatic retries** - Configurable exponential backoff
//! - **Connection pooling** - Efficient HTTP connection reuse
//! - **Authentication** - JWT and API key support
//! - **Streaming** - Stream large datasets efficiently
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use vault_sdk::{VaultClient, VaultConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), vault_sdk::Error> {
//!     // Create client with API key
//!     let client = VaultClient::builder()
//!         .base_url("https://vault.example.com")
//!         .api_key("your-api-key")
//!         .build()?;
//!
//!     // List datasets
//!     let datasets = client.datasets().list().await?;
//!
//!     for dataset in datasets.items {
//!         println!("Dataset: {} ({})", dataset.name, dataset.id);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Authentication
//!
//! The SDK supports multiple authentication methods:
//!
//! ### API Key
//! ```rust,no_run
//! # use vault_sdk::VaultClient;
//! let client = VaultClient::builder()
//!     .base_url("https://vault.example.com")
//!     .api_key("vk_live_xxxxx")
//!     .build()?;
//! # Ok::<(), vault_sdk::Error>(())
//! ```
//!
//! ### JWT Token
//! ```rust,no_run
//! # use vault_sdk::VaultClient;
//! let client = VaultClient::builder()
//!     .base_url("https://vault.example.com")
//!     .bearer_token("eyJ...")
//!     .build()?;
//! # Ok::<(), vault_sdk::Error>(())
//! ```
//!
//! ## Error Handling
//!
//! All operations return `Result<T, vault_sdk::Error>` with detailed error information:
//!
//! ```rust,no_run
//! # use vault_sdk::VaultClient;
//! # async fn example(client: VaultClient) {
//! match client.datasets().get("ds_123").await {
//!     Ok(dataset) => println!("Found: {}", dataset.name),
//!     Err(vault_sdk::Error::NotFound { .. }) => println!("Dataset not found"),
//!     Err(vault_sdk::Error::Unauthorized { .. }) => println!("Invalid credentials"),
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod auth;
pub mod client;
pub mod error;
pub mod models;

// Re-export main types
pub use client::{VaultClient, VaultClientBuilder, VaultConfig};
pub use error::Error;

// Re-export model types for convenience
pub use models::{
    Dataset, DatasetCreate, DatasetUpdate, DatasetList, DatasetStatus, DatasetFormat,
    Record, RecordCreate, RecordUpdate, RecordList, RecordStatus, RecordContent, PiiScanStatus, BulkRecordCreate,
    PiiDetectionResult, PiiDetectionRequest, PiiEntity, PiiType, AnonymizationRequest, AnonymizationResult, AnonymizationStrategy,
    Webhook, WebhookCreate, WebhookUpdate, WebhookList, WebhookEvent, WebhookDelivery, DeliveryStatus,
    ApiKey, ApiKeyCreate, ApiKeyList,
    User, TokenResponse,
    HealthStatus, ServiceStatus, Pagination, SortOrder,
};

/// SDK version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// User agent string for API requests
pub const USER_AGENT: &str = concat!("vault-sdk-rust/", env!("CARGO_PKG_VERSION"));
