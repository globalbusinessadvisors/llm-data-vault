# Architecture Overview

This document provides a comprehensive overview of LLM Data Vault's architecture, design decisions, and component interactions.

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Crate Structure](#crate-structure)
3. [Data Flow](#data-flow)
4. [Core Components](#core-components)
5. [Security Architecture](#security-architecture)
6. [Storage Architecture](#storage-architecture)
7. [Event System](#event-system)
8. [Design Decisions](#design-decisions)
9. [Scalability](#scalability)
10. [Future Considerations](#future-considerations)

---

## System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Client Layer                                   │
│    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│    │   Web Apps   │  │ ML Pipelines │  │     CLI      │               │
│    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘               │
└───────────┼─────────────────┼─────────────────┼─────────────────────────┘
            │                 │                 │
            └────────────────┬┴─────────────────┘
                             │ HTTPS
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        Load Balancer / Ingress                           │
│                         (TLS Termination)                                │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        LLM Data Vault Cluster                            │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    API Gateway Layer                             │   │
│  │  ┌─────────┐ ┌───────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │   │
│  │  │  Auth   │ │Rate Limit │ │ Logging │ │ Metrics │ │  CORS   │ │   │
│  │  └─────────┘ └───────────┘ └─────────┘ └─────────┘ └─────────┘ │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Application Layer                             │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │   │
│  │  │   Datasets   │  │   Records    │  │   Webhooks   │          │   │
│  │  │   Handler    │  │   Handler    │  │   Handler    │          │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Service Layer                                │   │
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │   │
│  │  │   Access    │ │ Anonymize   │ │   Crypto    │ │  Version  │ │   │
│  │  │   Control   │ │   (PII)     │ │ (Encrypt)   │ │  Control  │ │   │
│  │  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Storage Layer                                │   │
│  │  ┌─────────────────────────────────────────────────────────────┐│   │
│  │  │              Content-Addressable Storage                     ││   │
│  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐                  ││   │
│  │  │  │  Memory  │  │   File   │  │    S3    │                  ││   │
│  │  │  │ Backend  │  │ Backend  │  │ Backend  │                  ││   │
│  │  │  └──────────┘  └──────────┘  └──────────┘                  ││   │
│  │  └─────────────────────────────────────────────────────────────┘│   │
│  └─────────────────────────────────────────────────────────────────┘   │
└────────────────────────────┬──────────────────────┬────────────────────┘
                             │                      │
              ┌──────────────┴──────────┐   ┌──────┴──────┐
              ▼                         ▼   ▼             ▼
       ┌────────────┐           ┌────────────┐     ┌────────────┐
       │ PostgreSQL │           │   Redis    │     │   AWS S3   │
       │ (Metadata) │           │  (Cache)   │     │ (Content)  │
       └────────────┘           └────────────┘     └────────────┘
```

### Component Responsibilities

| Layer | Responsibility |
|-------|----------------|
| Client Layer | User interfaces, ML pipeline integration |
| Load Balancer | TLS termination, traffic distribution |
| API Gateway | Authentication, rate limiting, logging |
| Application Layer | Request handling, business logic |
| Service Layer | Core functionality, security services |
| Storage Layer | Data persistence, content addressing |

---

## Crate Structure

LLM Data Vault follows a modular architecture with clearly defined boundaries:

```
llm-data-vault/
├── crates/
│   ├── vault-core/           # Shared types and utilities
│   ├── vault-crypto/         # Cryptographic operations
│   ├── vault-storage/        # Storage backends
│   ├── vault-anonymize/      # PII detection & anonymization
│   ├── vault-access/         # Authentication & authorization
│   ├── vault-version/        # Versioning & lineage
│   ├── vault-integration/    # Events & webhooks
│   ├── vault-api/            # REST API layer
│   └── vault-server/         # Server binary
```

### Dependency Graph

```
                    vault-server
                         │
                         ▼
                    vault-api
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
    vault-access   vault-version   vault-integration
          │              │              │
          └──────┬───────┴───────┬──────┘
                 │               │
                 ▼               ▼
          vault-anonymize   vault-storage
                 │               │
                 └───────┬───────┘
                         │
                         ▼
                   vault-crypto
                         │
                         ▼
                    vault-core
```

### Crate Details

#### vault-core
Foundation crate providing:
- **Type IDs**: UUID-based identifiers for all entities
- **Error types**: Unified error handling with thiserror
- **Common traits**: Shared interfaces across crates
- **Utilities**: Time, validation, serialization helpers

```rust
// Example types
pub struct DatasetId(Uuid);
pub struct RecordId(Uuid);
pub struct UserId(Uuid);

// Error handling
pub enum VaultError {
    NotFound(String),
    Unauthorized(String),
    Validation(String),
    Internal(String),
}
```

#### vault-crypto
Cryptographic operations:
- **Encryption**: AES-256-GCM with authenticated encryption
- **KMS Integration**: AWS KMS for key management
- **Envelope Encryption**: Data keys encrypted by master keys
- **Key Caching**: Performance optimization for DEK lookups

```rust
// Key hierarchy
MasterKey (AWS KMS)
    └── DataEncryptionKey (per-object)
            └── Encrypted Data
```

#### vault-storage
Content-addressable storage:
- **Hash-based addressing**: Content identified by BLAKE3 hash
- **Deduplication**: Automatic at storage level
- **Multiple backends**: Memory, filesystem, S3
- **Streaming**: Large file support

```rust
pub trait ContentStore {
    async fn put(&self, content: &[u8]) -> Result<ContentAddress>;
    async fn get(&self, address: &ContentAddress) -> Result<Vec<u8>>;
    async fn exists(&self, address: &ContentAddress) -> Result<bool>;
}
```

#### vault-anonymize
PII detection and protection:
- **Pattern matching**: Regex-based detection for 15+ PII types
- **Context analysis**: Reduce false positives with surrounding text
- **Anonymization strategies**: Redaction, tokenization, k-anonymity
- **Compliance mapping**: GDPR, HIPAA, CCPA requirements

```rust
pub enum PIIType {
    Email,
    Phone,
    SSN,
    CreditCard,
    IPAddress,
    // ... more types
}

pub enum AnonymizationStrategy {
    Redact,
    Tokenize,
    Generalize,
    Mask,
}
```

#### vault-access
Access control:
- **Authentication**: JWT token management
- **RBAC**: Role-based permissions
- **ABAC**: Attribute-based policies
- **Multi-tenancy**: Organization isolation

```rust
pub struct Role {
    name: String,
    permissions: Vec<Permission>,
}

pub struct Permission {
    resource: Resource,
    action: Action,
    conditions: Vec<Condition>,
}
```

#### vault-version
Version control:
- **Git-like model**: Commits, branches, tags
- **Data lineage**: Track transformations
- **Immutable history**: Audit trail

```rust
pub struct Commit {
    id: CommitId,
    parent: Option<CommitId>,
    dataset_id: DatasetId,
    message: String,
    author: UserId,
    timestamp: DateTime<Utc>,
    snapshot: Snapshot,
}
```

#### vault-integration
External integrations:
- **Event bus**: Publish-subscribe pattern
- **Webhooks**: HTTP callbacks with retry
- **Notifications**: Event-driven updates

```rust
pub enum Event {
    DatasetCreated(DatasetId),
    RecordAdded(RecordId),
    PIIDetected(DetectionEvent),
    // ...
}
```

#### vault-api
REST API implementation:
- **Axum handlers**: Request processing
- **Middleware stack**: Auth, logging, metrics
- **OpenAPI generation**: Documentation

#### vault-server
Application entry point:
- **Configuration**: Multi-source config loading
- **Initialization**: Component wiring
- **Graceful shutdown**: Clean termination

---

## Data Flow

### Record Creation Flow

```
Client                API             Services           Storage
  │                    │                 │                  │
  │  POST /records     │                 │                  │
  │───────────────────►│                 │                  │
  │                    │                 │                  │
  │                    │  Authenticate   │                  │
  │                    │────────────────►│                  │
  │                    │◄────────────────│                  │
  │                    │                 │                  │
  │                    │  Authorize      │                  │
  │                    │────────────────►│                  │
  │                    │◄────────────────│                  │
  │                    │                 │                  │
  │                    │  Detect PII     │                  │
  │                    │────────────────►│                  │
  │                    │◄────────────────│                  │
  │                    │                 │                  │
  │                    │  Encrypt        │                  │
  │                    │────────────────►│                  │
  │                    │◄────────────────│                  │
  │                    │                 │                  │
  │                    │                 │  Store Content   │
  │                    │                 │─────────────────►│
  │                    │                 │◄─────────────────│
  │                    │                 │                  │
  │                    │                 │  Store Metadata  │
  │                    │                 │─────────────────►│
  │                    │                 │◄─────────────────│
  │                    │                 │                  │
  │                    │  Emit Event     │                  │
  │                    │────────────────►│                  │
  │                    │                 │                  │
  │  201 Created       │                 │                  │
  │◄───────────────────│                 │                  │
  │                    │                 │                  │
```

### PII Detection Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                         Input Text                                │
│    "Contact john.doe@email.com or call 555-123-4567"            │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                      Pattern Matching                             │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │  Email Regex   │  │  Phone Regex   │  │   SSN Regex    │ ... │
│  └────────┬───────┘  └────────┬───────┘  └────────────────┘     │
│           │                   │                                   │
│           ▼                   ▼                                   │
│    ┌────────────┐      ┌────────────┐                            │
│    │john.doe@   │      │555-123-4567│                            │
│    │email.com   │      │            │                            │
│    └────────────┘      └────────────┘                            │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Context Analysis                              │
│  - Check surrounding words                                        │
│  - Validate format                                                │
│  - Calculate confidence score                                     │
└────────────────────────────────┬─────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                      Detection Results                            │
│  [                                                                │
│    { type: "email", value: "john.doe@email.com", conf: 0.99 },  │
│    { type: "phone", value: "555-123-4567", conf: 0.95 }         │
│  ]                                                                │
└──────────────────────────────────────────────────────────────────┘
```

---

## Core Components

### Request Processing Pipeline

```rust
// Middleware stack (Axum/Tower)
let app = Router::new()
    .route("/api/v1/*", routes)
    .layer(
        ServiceBuilder::new()
            // Execute bottom to top
            .layer(TraceLayer::new())           // 5. Tracing
            .layer(MetricsLayer::new())         // 4. Metrics
            .layer(CompressionLayer::new())     // 3. Compression
            .layer(TimeoutLayer::new(30s))      // 2. Timeout
            .layer(CorsLayer::new())            // 1. CORS
    );
```

### Authentication Flow

```
┌──────────┐      ┌──────────┐      ┌──────────┐
│  Client  │      │   Auth   │      │  Token   │
│          │      │ Handler  │      │ Manager  │
└────┬─────┘      └────┬─────┘      └────┬─────┘
     │                 │                  │
     │  POST /login    │                  │
     │────────────────►│                  │
     │                 │                  │
     │                 │  Validate creds  │
     │                 │─────────────────►│
     │                 │                  │
     │                 │                  │ Check DB
     │                 │                  │────────►
     │                 │                  │◄────────
     │                 │                  │
     │                 │  Generate JWT    │
     │                 │─────────────────►│
     │                 │◄─────────────────│
     │                 │                  │
     │  { token: ... } │                  │
     │◄────────────────│                  │
     │                 │                  │
```

### Authorization Decision

```rust
// RBAC + ABAC evaluation
fn authorize(
    user: &User,
    resource: &Resource,
    action: Action,
    context: &Context,
) -> Decision {
    // 1. Check RBAC permissions
    if user.roles.iter().any(|r| r.permits(resource, action)) {
        // 2. Evaluate ABAC policies
        for policy in policies.matching(resource, action) {
            match policy.evaluate(user, resource, context) {
                PolicyResult::Deny => return Decision::Deny,
                PolicyResult::Allow => continue,
                PolicyResult::NotApplicable => continue,
            }
        }
        return Decision::Allow;
    }
    Decision::Deny
}
```

---

## Security Architecture

### Encryption Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    Transport Layer                           │
│                    TLS 1.3 / HTTPS                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                  Application Layer                     │  │
│  │               JWT Token Validation                     │  │
│  │  ┌─────────────────────────────────────────────────┐  │  │
│  │  │               Data Layer                         │  │  │
│  │  │           AES-256-GCM Encryption                 │  │  │
│  │  │  ┌───────────────────────────────────────────┐  │  │  │
│  │  │  │              Key Layer                     │  │  │  │
│  │  │  │         AWS KMS / Envelope Keys           │  │  │  │
│  │  │  │  ┌─────────────────────────────────────┐  │  │  │  │
│  │  │  │  │          Your Data                   │  │  │  │  │
│  │  │  │  └─────────────────────────────────────┘  │  │  │  │
│  │  │  └───────────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Envelope Encryption

```
┌─────────────────┐
│   Master Key    │  (AWS KMS - never leaves KMS)
│   (KEK)         │
└────────┬────────┘
         │ Encrypts
         ▼
┌─────────────────┐
│ Data Encryption │  (Generated per-object)
│     Key (DEK)   │
└────────┬────────┘
         │ Encrypts
         ▼
┌─────────────────┐
│   Your Data     │
│  (Ciphertext)   │
└─────────────────┘

Storage Format:
┌────────────────────────────────────────┐
│ Encrypted DEK │ Nonce │ Ciphertext │ Tag │
│   (256 bits)  │ (96b) │  (variable) │(128)│
└────────────────────────────────────────┘
```

---

## Storage Architecture

### Content-Addressable Storage

```
┌──────────────────────────────────────────────────────────────┐
│                      Content Flow                             │
│                                                               │
│   Input Data ──► BLAKE3 Hash ──► Content Address             │
│      │                               │                        │
│      │                               │                        │
│      ▼                               ▼                        │
│   Encrypt ──────────────────► Store by Address               │
│                                      │                        │
│                                      ▼                        │
│                               ┌──────────────┐               │
│                               │   Storage    │               │
│                               │   Backend    │               │
│                               └──────────────┘               │
└──────────────────────────────────────────────────────────────┘

Content Address = BLAKE3(content)
Example: "3b45c8a9f2..."
```

### Storage Backend Interface

```rust
#[async_trait]
pub trait ContentStore: Send + Sync {
    /// Store content and return its address
    async fn put(&self, content: &[u8]) -> Result<ContentAddress>;

    /// Retrieve content by address
    async fn get(&self, address: &ContentAddress) -> Result<Vec<u8>>;

    /// Check if content exists
    async fn exists(&self, address: &ContentAddress) -> Result<bool>;

    /// Delete content (with reference counting)
    async fn delete(&self, address: &ContentAddress) -> Result<()>;

    /// List all content addresses (for maintenance)
    async fn list(&self) -> Result<Vec<ContentAddress>>;
}
```

### Metadata vs Content Separation

```
┌─────────────────────────────────────────────────────────────┐
│                       PostgreSQL                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Metadata                          │   │
│  │  - Dataset info (name, description, owner)          │   │
│  │  - Record metadata (created, updated, PII flags)    │   │
│  │  - User accounts and permissions                     │   │
│  │  - Audit logs                                        │   │
│  │  - Content addresses (pointers to S3)               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ References
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         AWS S3                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Content                           │   │
│  │  - Encrypted data blobs                              │   │
│  │  - Addressed by content hash                         │   │
│  │  - Deduplicated automatically                        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Event System

### Event Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Producer   │     │  Event Bus   │     │  Consumer    │
│              │     │              │     │              │
│  API Handler │────►│   Channel    │────►│  Webhook     │
│              │     │              │     │  Dispatcher  │
└──────────────┘     └──────────────┘     └──────────────┘
                            │
                            │
                     ┌──────┴──────┐
                     ▼             ▼
              ┌──────────┐  ┌──────────┐
              │  Audit   │  │ Analytics│
              │  Logger  │  │ Tracker  │
              └──────────┘  └──────────┘
```

### Event Types

```rust
pub enum VaultEvent {
    // Dataset events
    DatasetCreated { id: DatasetId, name: String, owner: UserId },
    DatasetUpdated { id: DatasetId, changes: Vec<Change> },
    DatasetDeleted { id: DatasetId },

    // Record events
    RecordCreated { id: RecordId, dataset_id: DatasetId },
    RecordUpdated { id: RecordId, version: u64 },
    RecordDeleted { id: RecordId },

    // Security events
    PIIDetected { record_id: RecordId, pii_types: Vec<PIIType> },
    AccessDenied { user_id: UserId, resource: String, action: String },

    // System events
    WebhookDelivered { webhook_id: WebhookId, status: DeliveryStatus },
    HealthCheckFailed { component: String, error: String },
}
```

### Webhook Delivery

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│    Event     │     │   Webhook    │     │   External   │
│   Emitted    │────►│   Queue      │────►│   Endpoint   │
└──────────────┘     └──────┬───────┘     └──────────────┘
                            │
                            │ On failure
                            ▼
                     ┌──────────────┐
                     │    Retry     │
                     │    Queue     │
                     │              │
                     │  Backoff:    │
                     │  1m, 5m, 15m │
                     └──────────────┘
```

---

## Design Decisions

### Why Rust?

1. **Memory safety** without garbage collection
2. **Performance** comparable to C/C++
3. **Fearless concurrency** with ownership model
4. **Rich type system** for domain modeling
5. **Growing ecosystem** for cloud-native applications

### Why Content-Addressable Storage?

1. **Deduplication**: Identical content stored once
2. **Integrity**: Content hash verifies data
3. **Immutability**: Addresses never change
4. **Caching**: Content cacheable forever

### Why Envelope Encryption?

1. **Key rotation**: Rotate master key without re-encrypting data
2. **Performance**: Data keys cached locally
3. **Security**: Master key never leaves KMS
4. **Compliance**: Meets regulatory requirements

### Why Separate Metadata and Content?

1. **Query performance**: PostgreSQL optimized for queries
2. **Scale**: S3 handles large content efficiently
3. **Cost**: Hot metadata, cold content
4. **Backup**: Different strategies per tier

---

## Scalability

### Horizontal Scaling

```
                    Load Balancer
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌─────────┐     ┌─────────┐     ┌─────────┐
    │ Vault 1 │     │ Vault 2 │     │ Vault 3 │
    └────┬────┘     └────┬────┘     └────┬────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
         ┌────────┐ ┌────────┐ ┌────────┐
         │   PG   │ │ Redis  │ │   S3   │
         │Primary │ │Cluster │ │        │
         └────────┘ └────────┘ └────────┘
```

### Scaling Considerations

| Component | Scaling Strategy |
|-----------|------------------|
| API Servers | Horizontal (stateless) |
| PostgreSQL | Vertical + read replicas |
| Redis | Cluster mode |
| S3 | Infinite (managed) |

### Performance Targets

| Metric | Target |
|--------|--------|
| API latency (p99) | < 100ms |
| Throughput | 10,000 req/s |
| Storage | Petabyte scale |
| Availability | 99.9% |

---

## Future Considerations

### Planned Enhancements

1. **GraphQL API** - Alternative to REST for complex queries
2. **Streaming** - Server-sent events for real-time updates
3. **ML Integration** - Direct integration with training frameworks
4. **Multi-region** - Active-active deployment
5. **Plugin system** - Extensible PII detectors

### Technology Considerations

- **gRPC** - For service-to-service communication
- **Apache Arrow** - For columnar data processing
- **Delta Lake** - For data lakehouse integration

---

## See Also

- [API Reference](../api/openapi.yaml)
- [Configuration Reference](../deployment/CONFIGURATION.md)
- [Security Hardening](../security/HARDENING.md)
- [Operations Runbook](../operations/RUNBOOK.md)
