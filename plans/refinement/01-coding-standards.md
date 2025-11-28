# Coding Standards for LLM-Data-Vault

This document defines Rust coding standards for enterprise-grade, bug-free implementation of the LLM-Data-Vault project. All code must adhere to these standards to ensure reliability, maintainability, and security.

## 1. Project Structure

```
llm-data-vault/
├── Cargo.toml                 # Workspace configuration
├── .cargo/
│   └── config.toml            # Cargo configuration
├── crates/
│   ├── vault-core/            # Core domain types and traits
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── types/         # Domain types (ConversationId, MessageId, etc.)
│   │   │   ├── traits/        # Core traits (Storage, Crypto, etc.)
│   │   │   └── errors.rs      # Core error types
│   │   └── Cargo.toml
│   ├── vault-storage/         # Storage backend implementations
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── postgres/
│   │   │   ├── s3/
│   │   │   └── inmemory/      # For testing
│   │   └── Cargo.toml
│   ├── vault-crypto/          # Encryption and key management
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── aes_gcm.rs
│   │   │   ├── key_derivation.rs
│   │   │   └── secure_memory.rs
│   │   └── Cargo.toml
│   ├── vault-anonymize/       # PII detection and anonymization
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── detector/
│   │   │   ├── anonymizer/
│   │   │   └── patterns.rs
│   │   └── Cargo.toml
│   ├── vault-access/          # RBAC/ABAC implementation
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── rbac.rs
│   │   │   ├── abac.rs
│   │   │   └── policy.rs
│   │   └── Cargo.toml
│   ├── vault-api/             # REST and gRPC APIs
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── rest/
│   │   │   ├── grpc/
│   │   │   └── handlers/
│   │   └── Cargo.toml
│   ├── vault-version/         # Versioning and history
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── snapshot.rs
│   │   │   └── diff.rs
│   │   └── Cargo.toml
│   └── vault-integration/     # Events, webhooks, and integrations
│       ├── src/
│       │   ├── lib.rs
│       │   ├── events/
│       │   └── webhooks/
│       └── Cargo.toml
├── tests/                     # Integration tests
│   ├── common/
│   ├── storage_tests.rs
│   ├── crypto_tests.rs
│   └── end_to_end_tests.rs
├── benches/                   # Performance benchmarks
│   ├── storage_bench.rs
│   └── crypto_bench.rs
├── examples/                  # Usage examples
│   ├── basic_usage.rs
│   └── advanced_features.rs
└── docs/                      # Additional documentation
    ├── architecture.md
    └── api/
```

**Key Principles:**
- Each crate has a single, well-defined responsibility
- Dependencies flow inward (api → access → storage → core)
- Core types are dependency-free
- Test code lives alongside implementation with `#[cfg(test)]`

## 2. Rust Coding Conventions

### 2.1 Naming Conventions

```rust
// Types: PascalCase
struct ConversationId(uuid::Uuid);
enum StorageBackend { Postgres, S3 }
trait Encryptable {}

// Functions and variables: snake_case
fn encrypt_message(content: &str) -> Result<Vec<u8>> {}
let user_id = UserId::new();

// Constants: SCREAMING_SNAKE_CASE
const MAX_MESSAGE_SIZE: usize = 1_048_576; // 1 MB
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

// Lifetimes: short, lowercase
fn process<'a, 'ctx>(data: &'a Data, context: &'ctx Context) {}

// Type parameters: Single capital letter or PascalCase
fn transform<T>(value: T) -> T {}
fn convert<Input, Output>(input: Input) -> Output {}
```

### 2.2 Module Organization

```rust
// lib.rs - Public API surface
pub mod types;      // Re-export from types/mod.rs
pub mod errors;     // Error types
pub use types::*;   // Convenience re-exports

// Internal modules
mod utils;          // Private utilities
pub(crate) mod internal;  // Crate-visible internals

// Types module structure (types/mod.rs)
mod conversation_id;
mod message_id;
mod user_id;

pub use conversation_id::ConversationId;
pub use message_id::MessageId;
pub use user_id::UserId;
```

### 2.3 Visibility Rules

```rust
// Public API - visible to all consumers
pub struct PublicType;
pub fn public_function() {}

// Crate-visible - usable within the same crate
pub(crate) struct InternalType;
pub(crate) fn internal_helper() {}

// Module-visible - parent module only
pub(super) struct ParentAccessible;

// Private - default, same module only
struct PrivateType;
fn private_helper() {}
```

**Guidelines:**
- Start with minimal visibility, expand only when needed
- Use `pub(crate)` for internal APIs shared across modules
- Document why something is public if it's not obvious
- Never expose implementation details through public types

### 2.4 Documentation Requirements

```rust
/// Represents a unique conversation identifier.
///
/// This type wraps a UUID to provide type safety and prevent
/// mixing conversation IDs with other UUID-based identifiers.
///
/// # Examples
///
/// ```
/// use vault_core::ConversationId;
///
/// let id = ConversationId::new();
/// println!("Created conversation: {}", id);
/// ```
///
/// # Thread Safety
///
/// This type is `Send` and `Sync` and can be safely shared
/// across thread boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConversationId(uuid::Uuid);

impl ConversationId {
    /// Creates a new random conversation identifier.
    ///
    /// Uses UUIDv4 for random generation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vault_core::ConversationId;
    /// let id = ConversationId::new();
    /// assert!(!id.to_string().is_empty());
    /// ```
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Parses a conversation ID from a string.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string is not a valid UUID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use vault_core::ConversationId;
    /// let id = ConversationId::new();
    /// let parsed = ConversationId::parse_str(&id.to_string()).unwrap();
    /// assert_eq!(id, parsed);
    /// ```
    pub fn parse_str(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(uuid::Uuid::parse_str(s)?))
    }
}
```

**Documentation Requirements:**
- All public items must have `///` doc comments
- Include at least one usage example for public functions
- Document error conditions in an `# Errors` section
- Document panic conditions in a `# Panics` section
- Document safety requirements in a `# Safety` section (for unsafe code)
- Module-level docs explain purpose and usage patterns

## 3. Error Handling Standards

### 3.1 Error Type Structure

```rust
use thiserror::Error;

/// Core error type for vault operations.
///
/// Each variant includes an error code for programmatic handling.
#[derive(Error, Debug)]
pub enum VaultError {
    /// Storage operation failed.
    #[error("Storage error [{code}]: {message}")]
    Storage {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Encryption or decryption failed.
    #[error("Cryptography error [{code}]: {message}")]
    Crypto {
        code: ErrorCode,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Access control violation.
    #[error("Access denied [{code}]: {message}")]
    AccessDenied {
        code: ErrorCode,
        message: String,
        user_id: Option<String>,
        resource_id: Option<String>,
    },

    /// Invalid input or validation failure.
    #[error("Validation error [{code}]: {message}")]
    Validation {
        code: ErrorCode,
        message: String,
        field: Option<String>,
    },
}

/// Error codes for programmatic error handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    // Storage errors (1000-1999)
    StorageConnectionFailed = 1000,
    StorageQueryFailed = 1001,
    StorageNotFound = 1002,

    // Crypto errors (2000-2999)
    CryptoEncryptionFailed = 2000,
    CryptoDecryptionFailed = 2001,
    CryptoKeyDerivationFailed = 2002,

    // Access errors (3000-3999)
    AccessUnauthorized = 3000,
    AccessInsufficientPermissions = 3001,

    // Validation errors (4000-4999)
    ValidationInvalidInput = 4000,
    ValidationConstraintViolation = 4001,
}
```

### 3.2 Error Context Pattern

```rust
impl VaultError {
    /// Adds context to a storage error.
    pub fn storage_context<E>(source: E, context: &str) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Storage {
            code: ErrorCode::StorageQueryFailed,
            message: context.to_string(),
            source: Some(Box::new(source)),
        }
    }

    /// Creates a validation error with field information.
    pub fn validation(message: impl Into<String>, field: Option<&str>) -> Self {
        Self::Validation {
            code: ErrorCode::ValidationInvalidInput,
            message: message.into(),
            field: field.map(|s| s.to_string()),
        }
    }
}

// Usage
fn store_conversation(conv: &Conversation) -> Result<(), VaultError> {
    db.insert(conv)
        .map_err(|e| VaultError::storage_context(e, "Failed to insert conversation"))?;
    Ok(())
}
```

### 3.3 Result Type Alias

```rust
// Per-crate result type
pub type Result<T, E = VaultError> = std::result::Result<T, E>;

// Specific result types for different error domains
pub type StorageResult<T> = Result<T, StorageError>;
pub type CryptoResult<T> = Result<T, CryptoError>;
```

### 3.4 Never Panic in Libraries

```rust
// WRONG - panics on invalid input
pub fn encrypt(data: &[u8]) -> Vec<u8> {
    assert!(!data.is_empty(), "Data cannot be empty");
    // ...
}

// CORRECT - returns Result
pub fn encrypt(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(VaultError::validation("Data cannot be empty", None));
    }
    // ...
}

// ACCEPTABLE - panic on programming errors (bugs)
fn internal_invariant_check(value: usize) {
    debug_assert!(value < MAX_VALUE, "Internal invariant violated");
}
```

## 4. Async Patterns

### 4.1 Background Tasks

```rust
use tokio::task::JoinSet;

/// Spawns a background task with error handling.
pub async fn process_events(events: Vec<Event>) -> Result<()> {
    let mut tasks = JoinSet::new();

    for event in events {
        tasks.spawn(async move {
            process_event(event).await
        });
    }

    // Wait for all tasks, collecting errors
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {},
            Ok(Err(e)) => log::error!("Event processing failed: {}", e),
            Err(e) => log::error!("Task panicked: {}", e),
        }
    }

    Ok(())
}
```

### 4.2 Cancellation Pattern

```rust
use tokio_util::sync::CancellationToken;

pub struct Service {
    cancel_token: CancellationToken,
}

impl Service {
    pub async fn run(&self) -> Result<()> {
        tokio::select! {
            result = self.do_work() => result,
            _ = self.cancel_token.cancelled() => {
                log::info!("Service shutdown requested");
                Ok(())
            }
        }
    }

    pub fn shutdown(&self) {
        self.cancel_token.cancel();
    }
}
```

### 4.3 Timeout Pattern

```rust
use tokio::time::{timeout, Duration};

pub async fn fetch_with_timeout(url: &str) -> Result<String> {
    let operation = async {
        // Network operation
        reqwest::get(url).await?.text().await
    };

    timeout(Duration::from_secs(30), operation)
        .await
        .map_err(|_| VaultError::validation("Operation timed out", None))?
        .map_err(|e| VaultError::storage_context(e, "Network request failed"))
}
```

### 4.4 Runtime Rules

```rust
// WRONG - blocks the runtime
pub async fn read_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)  // Blocking I/O!
        .map_err(|e| VaultError::storage_context(e, "File read failed"))
}

// CORRECT - use async I/O
pub async fn read_file(path: &Path) -> Result<String> {
    tokio::fs::read_to_string(path).await
        .map_err(|e| VaultError::storage_context(e, "File read failed"))
}

// CORRECT - offload blocking work
pub async fn compute_hash(data: &[u8]) -> Result<String> {
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || {
        // CPU-intensive work
        expensive_hash(&data)
    })
    .await
    .map_err(|e| VaultError::storage_context(e, "Hash computation failed"))?
}
```

## 5. Memory Safety

### 5.1 Secure String Handling

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure string that zeros memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

// Usage for passwords, API keys, encryption keys
pub struct Credentials {
    username: String,
    password: SecureString,  // Zeroed on drop
}
```

### 5.2 Collection Capacity

```rust
// WRONG - unbounded growth
pub fn collect_messages(stream: impl Stream<Item = Message>) -> Vec<Message> {
    stream.collect().await  // Could exhaust memory!
}

// CORRECT - bounded with explicit capacity
pub fn collect_messages(
    stream: impl Stream<Item = Message>,
    max_messages: usize,
) -> Result<Vec<Message>> {
    let mut messages = Vec::with_capacity(max_messages.min(1000));

    pin_mut!(stream);
    while let Some(msg) = stream.next().await {
        if messages.len() >= max_messages {
            return Err(VaultError::validation("Too many messages", None));
        }
        messages.push(msg);
    }

    Ok(messages)
}

// CORRECT - pre-allocate when size is known
pub fn process_batch(count: usize) -> Vec<ProcessedItem> {
    let mut items = Vec::with_capacity(count);
    for i in 0..count {
        items.push(process_item(i));
    }
    items
}
```

### 5.3 Resource Cleanup

```rust
pub struct EncryptionContext {
    key_material: SecureString,
    temp_buffer: Vec<u8>,
}

impl Drop for EncryptionContext {
    fn drop(&mut self) {
        // Explicit cleanup of sensitive data
        self.temp_buffer.zeroize();
        log::debug!("Encryption context cleaned up");
    }
}
```

## 6. Type Safety

### 6.1 Newtype Pattern for IDs

```rust
use std::fmt;

/// Conversation identifier (prevents mixing with other UUIDs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConversationId(uuid::Uuid);

/// User identifier (distinct type from ConversationId).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UserId(uuid::Uuid);

// Compiler prevents mixing:
fn get_conversation(id: ConversationId) -> Conversation { /* ... */ }

let user_id = UserId::new();
// get_conversation(user_id);  // Compile error!
```

### 6.2 Builder Pattern

```rust
/// Configuration builder for storage backend.
pub struct StorageConfigBuilder {
    connection_string: Option<String>,
    max_connections: Option<u32>,
    timeout: Option<Duration>,
}

impl StorageConfigBuilder {
    pub fn new() -> Self {
        Self {
            connection_string: None,
            max_connections: None,
            timeout: None,
        }
    }

    pub fn connection_string(mut self, s: impl Into<String>) -> Self {
        self.connection_string = Some(s.into());
        self
    }

    pub fn max_connections(mut self, n: u32) -> Self {
        self.max_connections = Some(n);
        self
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    pub fn build(self) -> Result<StorageConfig> {
        Ok(StorageConfig {
            connection_string: self.connection_string
                .ok_or_else(|| VaultError::validation("connection_string required", None))?,
            max_connections: self.max_connections.unwrap_or(10),
            timeout: self.timeout.unwrap_or(Duration::from_secs(30)),
        })
    }
}

// Usage
let config = StorageConfigBuilder::new()
    .connection_string("postgresql://localhost")
    .max_connections(20)
    .build()?;
```

### 6.3 State Machine with Phantom Types

```rust
use std::marker::PhantomData;

/// Represents different states of a conversation.
pub struct Draft;
pub struct Active;
pub struct Archived;

/// Type-safe conversation with state tracking.
pub struct Conversation<State = Draft> {
    id: ConversationId,
    data: ConversationData,
    _state: PhantomData<State>,
}

impl Conversation<Draft> {
    pub fn new(id: ConversationId) -> Self {
        Self {
            id,
            data: ConversationData::default(),
            _state: PhantomData,
        }
    }

    pub fn activate(self) -> Conversation<Active> {
        Conversation {
            id: self.id,
            data: self.data,
            _state: PhantomData,
        }
    }
}

impl Conversation<Active> {
    pub fn add_message(&mut self, msg: Message) {
        // Only active conversations can receive messages
        self.data.messages.push(msg);
    }

    pub fn archive(self) -> Conversation<Archived> {
        Conversation {
            id: self.id,
            data: self.data,
            _state: PhantomData,
        }
    }
}

impl Conversation<Archived> {
    // Archived conversations are read-only
    pub fn messages(&self) -> &[Message] {
        &self.data.messages
    }
}
```

### 6.4 Validated Numbers

```rust
use std::num::NonZeroU32;

/// Page size must be non-zero.
pub struct PaginationConfig {
    page_size: NonZeroU32,  // Compile-time guarantee > 0
    max_pages: NonZeroU32,
}

impl PaginationConfig {
    pub fn new(page_size: u32, max_pages: u32) -> Result<Self> {
        Ok(Self {
            page_size: NonZeroU32::new(page_size)
                .ok_or_else(|| VaultError::validation("page_size must be > 0", None))?,
            max_pages: NonZeroU32::new(max_pages)
                .ok_or_else(|| VaultError::validation("max_pages must be > 0", None))?,
        })
    }
}
```

## 7. Testing Requirements

### 7.1 Unit Tests Structure

```rust
// In the same file as implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversation_id_creation() {
        let id = ConversationId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn test_conversation_id_parsing() {
        let id = ConversationId::new();
        let parsed = ConversationId::parse_str(&id.to_string()).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_invalid_conversation_id() {
        let result = ConversationId::parse_str("invalid");
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod async_tests {
    use super::*;

    #[tokio::test]
    async fn test_async_operation() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

### 7.2 Coverage Requirements

**Minimum 90% code coverage for all crates.**

Configure with `cargo-tarpaulin`:

```toml
# .cargo/config.toml
[build]
rustflags = ["-C", "instrument-coverage"]

[test]
# Fail if coverage drops below 90%
cargo-tarpaulin --fail-under 90
```

### 7.3 Property-Based Testing

```rust
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_encryption_roundtrip(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let key = generate_key();
            let encrypted = encrypt(&data, &key).unwrap();
            let decrypted = decrypt(&encrypted, &key).unwrap();
            assert_eq!(data, decrypted);
        }

        #[test]
        fn test_conversation_id_roundtrip(uuid_str in "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}") {
            if let Ok(id) = ConversationId::parse_str(&uuid_str) {
                let serialized = id.to_string();
                let parsed = ConversationId::parse_str(&serialized).unwrap();
                assert_eq!(id, parsed);
            }
        }
    }
}
```

### 7.4 Mocking

```rust
use mockall::predicate::*;
use mockall::*;

#[automock]
pub trait StorageBackend {
    async fn get_conversation(&self, id: ConversationId) -> Result<Conversation>;
    async fn store_conversation(&self, conv: &Conversation) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_with_mock_storage() {
        let mut mock = MockStorageBackend::new();

        mock.expect_get_conversation()
            .with(eq(ConversationId::new()))
            .times(1)
            .returning(|_| Ok(Conversation::default()));

        let service = Service::new(Box::new(mock));
        let result = service.fetch_conversation(ConversationId::new()).await;
        assert!(result.is_ok());
    }
}
```

## 8. Documentation

### 8.1 Module-Level Documentation

```rust
//! Core types for LLM-Data-Vault.
//!
//! This module provides the foundational types used throughout the vault system:
//! - Identifiers (ConversationId, MessageId, UserId)
//! - Domain objects (Conversation, Message, User)
//! - Configuration types
//!
//! # Examples
//!
//! ```
//! use vault_core::{ConversationId, Conversation};
//!
//! let id = ConversationId::new();
//! let conv = Conversation::new(id);
//! ```
//!
//! # Architecture
//!
//! The core crate is dependency-free and defines only types and traits.
//! Implementations are provided in separate crates (vault-storage,
//! vault-crypto, etc.).

pub mod types;
pub mod traits;
pub mod errors;
```

### 8.2 CHANGELOG Maintenance

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New feature X
- Support for Y

### Changed
- Improved performance of Z

### Deprecated
- Function A is deprecated, use B instead

### Removed
- Removed deprecated function C

### Fixed
- Fixed bug in D

### Security
- Fixed security vulnerability in E

## [0.2.0] - 2025-01-15

### Added
- Initial implementation of vault-crypto
- AES-GCM encryption support

## [0.1.0] - 2025-01-01

### Added
- Initial release
- Basic conversation storage
```

## 9. Linting & Formatting

### 9.1 rustfmt Configuration

```toml
# rustfmt.toml
edition = "2021"
max_width = 100
hard_tabs = false
tab_spaces = 4
newline_style = "Unix"
use_small_heuristics = "Default"
reorder_imports = true
reorder_modules = true
remove_nested_parens = true
format_code_in_doc_comments = true
normalize_comments = true
wrap_comments = true
comment_width = 80
```

### 9.2 Clippy Configuration

```toml
# Cargo.toml
[lints.clippy]
# Deny
pedantic = "deny"
nursery = "deny"
cargo = "deny"

# Specific lints
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"

# Allow some pedantic lints that are too strict
module_name_repetitions = "allow"
must_use_candidate = "allow"
```

### 9.3 Safety Configuration

```toml
# Cargo.toml for library crates
[lints.rust]
unsafe_code = "forbid"
missing_docs = "deny"
missing_debug_implementations = "deny"

# For specific crates that need unsafe (e.g., vault-crypto)
[lints.rust]
unsafe_code = "deny"  # Deny but allow with #[allow(unsafe_code)]
```

### 9.4 CI Checks

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy

      - name: Format check
        run: cargo fmt --all -- --check

      - name: Clippy
        run: cargo clippy --all-targets --all-features -- -D warnings

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Run tests
        run: cargo test --all-features

      - name: Coverage
        run: |
          cargo install cargo-tarpaulin
          cargo tarpaulin --all-features --fail-under 90 --out Xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Security audit
        run: |
          cargo install cargo-audit
          cargo audit
```

## 10. Dependencies

### 10.1 Minimal Dependencies Policy

**Guidelines:**
- Evaluate necessity before adding any dependency
- Prefer standard library solutions when available
- Choose well-maintained crates with security track records
- Avoid dependencies with excessive transitive dependencies

**Approved Core Dependencies:**
```toml
# Async runtime
tokio = { version = "1.35", features = ["full"] }

# Error handling
thiserror = "1.0"
anyhow = "1.0"  # Binaries only, not libraries

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Crypto
aes-gcm = "0.10"
argon2 = "0.5"
zeroize = { version = "1.7", features = ["derive"] }

# Database
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio"] }

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Testing
proptest = "1.4"
mockall = "0.12"
```

### 10.2 Security Audit Requirements

**Required checks:**
1. Run `cargo audit` on every build
2. Review security advisories weekly
3. Update dependencies monthly
4. Pin versions for reproducible builds

```toml
# Cargo.toml
[dependencies]
# Pin exact versions for critical dependencies
aes-gcm = "=0.10.3"

# Use caret requirements for non-critical
serde = "^1.0.195"
```

### 10.3 Version Pinning Strategy

```toml
# Development dependencies can be more permissive
[dev-dependencies]
proptest = "1.4"
criterion = "0.5"

# Production dependencies should be pinned
[dependencies]
tokio = "=1.35.1"
sqlx = "=0.7.3"

# Workspace dependencies for consistency
[workspace.dependencies]
vault-core = { path = "./crates/vault-core", version = "0.1.0" }
tokio = { version = "1.35", features = ["full"] }
```

### 10.4 Dependency Review Process

Before adding a dependency, verify:

1. **Maintenance**: Last commit within 6 months
2. **Security**: No known vulnerabilities
3. **License**: Compatible with project license
4. **Alternatives**: Compare with alternative crates
5. **Size**: Check impact on compile time and binary size

```bash
# Check dependency tree
cargo tree

# Check for outdated dependencies
cargo outdated

# Check for security vulnerabilities
cargo audit

# Check licenses
cargo-license
```

## 11. Code Review Checklist

Before submitting code for review, verify:

- [ ] All public APIs are documented with examples
- [ ] Error handling uses Result, never panics
- [ ] Tests achieve 90%+ coverage
- [ ] `cargo fmt` passes
- [ ] `cargo clippy` passes with zero warnings
- [ ] `cargo test` passes
- [ ] `cargo audit` shows no vulnerabilities
- [ ] CHANGELOG.md is updated
- [ ] No `TODO` or `FIXME` comments in production code
- [ ] No `println!` or `dbg!` in production code (use `tracing`)
- [ ] Async code doesn't block the runtime
- [ ] Sensitive data uses `SecureString` or `Zeroize`
- [ ] Collections have explicit capacity limits
- [ ] All unwrap/expect are justified with comments

---

**Document Version:** 1.0
**Last Updated:** 2025-11-27
**Status:** Active
