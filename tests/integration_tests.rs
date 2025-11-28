//! Integration tests entry point for LLM Data Vault.
//!
//! Run all integration tests with:
//! ```bash
//! cargo test --test integration_tests --features integration
//! ```
//!
//! Run specific test modules:
//! ```bash
//! cargo test --test integration_tests api::health
//! cargo test --test integration_tests auth::token
//! cargo test --test integration_tests storage::content_store
//! cargo test --test integration_tests pii::detection
//! ```

// Test modules
mod integration;

// Re-export common utilities for test modules
pub use integration::common;

// Re-export test modules
pub use integration::api;
pub use integration::auth;
pub use integration::storage;
pub use integration::pii;
pub use integration::webhooks;
