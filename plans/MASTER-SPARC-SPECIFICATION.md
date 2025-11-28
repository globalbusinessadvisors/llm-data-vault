# LLM-Data-Vault: Master SPARC Specification

**Module:** LLM-Data-Vault
**Version:** 1.0.0
**Status:** Complete
**Date:** 2025-11-27
**Methodology:** SPARC (Specification, Pseudocode, Architecture, Refinement, Completion)

---

## Executive Summary

LLM-Data-Vault is an enterprise-grade, cryptographically secure storage and anonymization layer for managing datasets, prompts, evaluation corpora, and conversational data within the LLM DevOps ecosystem. This master specification document consolidates all SPARC methodology phases into a single comprehensive reference.

### Document Statistics

| Phase | Documents | Approximate Lines | Purpose |
|-------|-----------|-------------------|---------|
| **S**pecification | 1 | ~665 | Requirements and objectives |
| **P**seudocode | 9 | ~8,000 | Implementation algorithms |
| **A**rchitecture | 8 | ~6,500 | System design |
| **R**efinement | 9 | ~6,000 | Quality standards |
| **C**ompletion | 9 | ~5,500 | Implementation artifacts |
| **Total** | **36** | **~26,665** | Full specification |

### Key Capabilities

- **Secure Storage**: AES-256-GCM encryption at rest, TLS 1.3 in transit
- **PII Anonymization**: 99.5%+ detection accuracy with multiple strategies
- **Version Control**: Git-like versioning with full data lineage
- **Access Control**: RBAC + ABAC with enterprise identity integration
- **High Performance**: 10,000 req/s, p99 < 200ms latency
- **Compliance**: GDPR, HIPAA, SOC 2, PCI-DSS ready

---

## Table of Contents

1. [Part 1: Specification](#part-1-specification)
2. [Part 2: Pseudocode](#part-2-pseudocode)
3. [Part 3: Architecture](#part-3-architecture)
4. [Part 4: Refinement](#part-4-refinement)
5. [Part 5: Completion](#part-5-completion)
6. [Appendices](#appendices)

---

# Part 1: Specification

## 1.1 Purpose

LLM-Data-Vault is a secure, enterprise-grade storage and anonymization layer for managing datasets, prompts, evaluation corpora, and conversational data within the LLM DevOps ecosystem. It provides cryptographically secure storage with built-in anonymization capabilities, ensuring safe data retention, versioning, and sharing while maintaining compliance with GDPR, HIPAA, and CCPA.

**Core Value Proposition**: Privacy-preserving data management that transforms data from a liability into a strategic asset by enabling:
- Comprehensive dataset building for model evaluation and fine-tuning without exposing sensitive information
- Secure corpus sharing across teams and external partners for collaborative benchmarking
- Complete audit trails for regulatory compliance
- Decoupled data storage from model operations with strict access controls

## 1.2 Scope

### In Scope

| Capability | Description |
|------------|-------------|
| **Secure Storage** | Encrypted at-rest and in-transit storage supporting S3, Azure Blob, GCS, on-premises |
| **PII Detection & Anonymization** | Automatic detection and redaction with configurable strategies |
| **Version Control** | Git-like versioning with content-addressable storage, branching, tagging |
| **Access Control** | RBAC and ABAC with enterprise identity provider integration |
| **Data Lineage** | Complete audit trails with cryptographic integrity verification |
| **Query APIs** | High-performance interfaces supporting batch operations and streaming |
| **Export & Sharing** | Secure export with watermarking and time-limited access tokens |
| **Compliance** | Automated enforcement of retention policies and RTBF requirements |

### Out of Scope

- Model training execution and fine-tuning pipelines
- Real-time model inference and serving
- Model deployment and orchestration
- Active performance monitoring
- Prompt engineering and optimization tools
- Data synthesis and generation

## 1.3 Problem Definition

Organizations deploying LLMs face an impossible choice: retain comprehensive datasets for model improvement while creating privacy liabilities, or aggressively delete data while sacrificing diagnostic capabilities.

**Critical Gaps in Existing Solutions**:
- General-purpose databases lack LLM-specific anonymization
- Data lakes provide storage without privacy transformations
- PII redaction services operate as external preprocessing steps
- ML feature stores focus on training features, not raw data

LLM-Data-Vault fills this gap by treating privacy as a first-class storage property.

## 1.4 Objectives

### Primary Objectives

1. **Encryption-at-rest**: AES-256-GCM for all stored data
2. **Access policy enforcement**: Granular RBAC and ABAC
3. **Automated anonymization**: Intelligent PII detection (99.5%+ accuracy)
4. **Version control**: Comprehensive history with cryptographic integrity
5. **Secure sharing**: Controlled sharing with provenance tracking

### Secondary Objectives

1. Audit logging and compliance reporting
2. External key management integration (AWS KMS, HashiCorp Vault, Azure Key Vault)
3. Multiple storage backend support
4. Performance optimization for large datasets
5. API-first design with SDK generation

## 1.5 Users & Roles

### Primary Users

| Role | Use Cases | Key Permissions |
|------|-----------|-----------------|
| **Data Scientists** | Upload datasets, search/retrieve anonymized data, export sanitized subsets | Read/Write own & shared, execute anonymization |
| **ML Engineers** | Integrate APIs, configure anonymization policies, monitor access | Read/Write production, configure policies |
| **Auditors** | Review access events, verify compliance, generate reports | Read-only all, full audit log access |

### RBAC Matrix

| Role | Read | Write | Delete | Anonymize | Audit | Admin |
|------|------|-------|--------|-----------|-------|-------|
| Data Scientist | Own & Shared | Own & Shared | Own Only | Own & Shared | Own | No |
| ML Engineer | Production | Production | No | Configure | Team | No |
| Auditor | All (RO) | No | No | No | All | No |
| Platform Admin | All | No | No | No | Admin | Yes |

## 1.6 Dependencies & Integration Points

### Internal Modules

| Module | Integration | Protocol |
|--------|-------------|----------|
| LLM-Registry | Dataset registration, model linking | gRPC, Events |
| LLM-Policy-Engine | Policy evaluation, compliance | gRPC |
| LLM-Analytics-Hub | Usage metrics, audit events | Events |
| LLM-Governance-Dashboard | Compliance reporting, lineage | REST, Events |

### External Dependencies

| Category | Providers |
|----------|-----------|
| Key Management | AWS KMS, HashiCorp Vault, Azure Key Vault, GCP KMS |
| Storage | AWS S3, Azure Blob, GCS, MinIO |
| Authentication | OIDC (Okta, Auth0), LDAP, SAML 2.0, mTLS |
| Messaging | Apache Kafka, RabbitMQ, AWS SQS/SNS |

## 1.7 Design Principles

### Core Principles

| Principle | Implementation |
|-----------|----------------|
| **Zero-Trust** | All requests authenticated/authorized, mTLS, short-lived JWTs |
| **Modularity** | Pluggable storage, encryption, and anonymization providers |
| **Interoperability** | OpenAPI 3.0, Protocol Buffers, CloudEvents |
| **Defense in Depth** | Multiple security layers, redundant controls |
| **Encryption by Default** | AES-256-GCM at rest, TLS 1.3 in transit |
| **Observable** | Prometheus metrics, OpenTelemetry tracing, structured logging |

## 1.8 Success Metrics

### Key Performance Indicators

| Category | Metric | Target |
|----------|--------|--------|
| **Security** | Data breaches | 0 |
| **Security** | PII detection accuracy | ≥ 99.5% |
| **Security** | Encryption coverage | 100% |
| **Performance** | API latency (p99) | < 200ms |
| **Performance** | Throughput | 10,000 req/s |
| **Availability** | System uptime | ≥ 99.9% |
| **Availability** | MTTR | < 15 min |
| **Compliance** | Audit pass rate | 100% |

---

# Part 2: Pseudocode

## 2.1 Core Data Models

### Type-Safe Identifiers (Newtype Pattern)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DatasetId(pub Uuid);
pub struct VersionId(pub Uuid);
pub struct RecordId(pub Uuid);
pub struct UserId(pub Uuid);
pub struct TenantId(pub Uuid);
```

### Dataset Entity

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    pub id: DatasetId,
    pub tenant_id: TenantId,
    pub name: String,
    pub description: Option<String>,
    pub schema: Option<DatasetSchema>,
    pub current_version: VersionId,
    pub status: DatasetStatus,
    pub tags: Vec<Tag>,
    pub metadata: Metadata,
    pub encryption_key_id: KeyId,
    pub created_at: DateTime<Utc>,
    pub created_by: UserId,
}

impl Dataset {
    pub fn builder() -> DatasetBuilder { DatasetBuilder::default() }
    pub fn validate(&self) -> Result<(), ValidationError> { /* ... */ }
}
```

### Schema Definition

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSchema {
    pub version: String,
    pub fields: Vec<SchemaField>,
    pub primary_key: Option<Vec<String>>,
}

pub struct SchemaField {
    pub name: String,
    pub field_type: FieldType,
    pub nullable: bool,
    pub pii_classification: Option<PIIClassification>,
    pub constraints: Vec<FieldConstraint>,
}

pub enum FieldType {
    String, Integer, Float, Boolean, Timestamp,
    Array(Box<FieldType>),
    Struct(Vec<SchemaField>),
}
```

### Data Record

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRecord {
    pub id: RecordId,
    pub dataset_id: DatasetId,
    pub version_id: VersionId,
    pub data: RecordData,
    pub checksum: Checksum,
    pub pii_annotations: Option<Vec<PIIAnnotation>>,
    pub created_at: DateTime<Utc>,
}

pub enum RecordData {
    Structured(serde_json::Value),
    Text(String),
    Binary(Vec<u8>),
}
```

## 2.2 Storage Layer

### Storage Backend Trait

```rust
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn put(&self, key: &StorageKey, data: Bytes, options: PutOptions)
        -> Result<StorageReceipt, StorageError>;
    async fn get(&self, key: &StorageKey) -> Result<Bytes, StorageError>;
    async fn get_stream(&self, key: &StorageKey)
        -> Result<Pin<Box<dyn Stream<Item = Result<Bytes>>>>, StorageError>;
    async fn delete(&self, key: &StorageKey) -> Result<(), StorageError>;
    async fn exists(&self, key: &StorageKey) -> Result<bool, StorageError>;
    async fn list(&self, prefix: &str) -> Result<Vec<StorageKey>, StorageError>;
}
```

### Content-Addressable Storage

```rust
pub struct ContentAddressableStore {
    backend: Arc<dyn StorageBackend>,
    algorithm: HashAlgorithm,  // Blake3 default
}

impl ContentAddressableStore {
    pub async fn put(&self, data: Bytes) -> Result<ContentHash, StorageError> {
        let hash = ContentHash::compute(&data, self.algorithm);
        let key = StorageKey::from_content_hash(&hash);

        // Automatic deduplication
        if !self.backend.exists(&key).await? {
            self.backend.put(&key, data, PutOptions::default()).await?;
        }

        Ok(hash)
    }

    pub async fn get(&self, hash: &ContentHash) -> Result<Bytes, StorageError> {
        let key = StorageKey::from_content_hash(hash);
        let data = self.backend.get(&key).await?;

        // Verify integrity
        let computed = ContentHash::compute(&data, self.algorithm);
        if computed != *hash {
            return Err(StorageError::IntegrityError);
        }

        Ok(data)
    }
}
```

### Chunked Storage for Large Files

```rust
pub struct ChunkManager {
    cas: Arc<ContentAddressableStore>,
    chunk_size: usize,  // Default 64MB
}

pub struct ChunkManifest {
    pub chunks: Vec<ChunkInfo>,
    pub total_size: u64,
    pub checksum: Checksum,
}

impl ChunkManager {
    pub async fn store(&self, data: Bytes) -> Result<ChunkManifest, StorageError> {
        let mut chunks = Vec::new();

        for chunk in data.chunks(self.chunk_size) {
            let hash = self.cas.put(Bytes::copy_from_slice(chunk)).await?;
            chunks.push(ChunkInfo { hash, size: chunk.len() });
        }

        Ok(ChunkManifest { chunks, total_size: data.len() as u64, checksum: Checksum::compute(&data) })
    }

    pub async fn retrieve(&self, manifest: &ChunkManifest) -> Result<Bytes, StorageError> {
        let mut data = BytesMut::with_capacity(manifest.total_size as usize);

        for chunk_info in &manifest.chunks {
            let chunk = self.cas.get(&chunk_info.hash).await?;
            data.extend_from_slice(&chunk);
        }

        // Verify integrity
        let computed = Checksum::compute(&data);
        if computed != manifest.checksum {
            return Err(StorageError::IntegrityError);
        }

        Ok(data.freeze())
    }
}
```

## 2.3 Encryption & Security

### Encryption Provider Trait

```rust
#[async_trait]
pub trait EncryptionProvider: Send + Sync {
    async fn encrypt(&self, plaintext: &[u8], context: &EncryptionContext)
        -> Result<EncryptedData, CryptoError>;
    async fn decrypt(&self, ciphertext: &EncryptedData, context: &EncryptionContext)
        -> Result<SecureBytes, CryptoError>;
    async fn generate_data_key(&self) -> Result<DataKey, CryptoError>;
}
```

### Secure Memory with Zeroization

```rust
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    pub fn new(data: Vec<u8>) -> Self { Self(data) }
    pub fn as_slice(&self) -> &[u8] { &self.0 }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey {
    pub plaintext: SecureBytes,
    pub encrypted: Vec<u8>,
    pub key_id: KeyId,
}
```

### Envelope Encryption

```rust
pub struct EnvelopeEncryption {
    kms: Arc<dyn KmsProvider>,
    master_key_id: KeyId,
    dek_cache: Arc<RwLock<LruCache<KeyId, CachedDek>>>,
}

impl EnvelopeEncryption {
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<EnvelopeEncryptedData, CryptoError> {
        // Generate DEK via KMS
        let dek = self.kms.generate_data_key(&self.master_key_id).await?;

        // Generate nonce
        let nonce: [u8; 12] = rand::random();

        // Encrypt data with DEK using AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(dek.plaintext.as_slice())?;
        let ciphertext = cipher.encrypt(&nonce.into(), plaintext)?;

        Ok(EnvelopeEncryptedData {
            encrypted_dek: dek.encrypted,
            ciphertext,
            nonce: nonce.to_vec(),
            key_id: dek.key_id,
        })
    }

    pub async fn decrypt(&self, data: &EnvelopeEncryptedData) -> Result<SecureBytes, CryptoError> {
        // Get DEK from cache or decrypt via KMS
        let dek = self.get_or_decrypt_dek(&data.key_id, &data.encrypted_dek).await?;

        // Decrypt data
        let cipher = Aes256Gcm::new_from_slice(dek.as_slice())?;
        let nonce = GenericArray::from_slice(&data.nonce);
        let plaintext = cipher.decrypt(nonce, data.ciphertext.as_slice())?;

        Ok(SecureBytes::new(plaintext))
    }
}
```

### KMS Provider Trait

```rust
#[async_trait]
pub trait KmsProvider: Send + Sync {
    async fn generate_data_key(&self, key_id: &KeyId) -> Result<DataKey, CryptoError>;
    async fn decrypt_data_key(&self, key_id: &KeyId, encrypted: &[u8]) -> Result<SecureBytes, CryptoError>;
    async fn encrypt(&self, key_id: &KeyId, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError>;
    async fn create_key(&self, config: KeyConfig) -> Result<KeyId, CryptoError>;
    async fn rotate_key(&self, key_id: &KeyId) -> Result<KeyId, CryptoError>;
}

// Implementations: AwsKmsProvider, VaultKmsProvider, AzureKeyVaultProvider, LocalKmsProvider
```

## 2.4 Anonymization Engine

### PII Detector Trait

```rust
pub trait PIIDetector: Send + Sync {
    fn detect(&self, text: &str) -> Vec<PIIMatch>;
    fn supported_types(&self) -> Vec<PIIType>;
}

#[derive(Debug, Clone)]
pub struct PIIMatch {
    pub pii_type: PIIType,
    pub span: Range<usize>,
    pub text: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PIIType {
    Email, PhoneNumber, SSN, CreditCard, Name, Address,
    DateOfBirth, APIKey, IPAddress, MedicalRecordNumber,
}
```

### Regex-Based Detector

```rust
pub struct RegexPIIDetector {
    patterns: Vec<PIIPattern>,
    validators: HashMap<PIIType, Box<dyn Fn(&str) -> bool>>,
}

impl PIIDetector for RegexPIIDetector {
    fn detect(&self, text: &str) -> Vec<PIIMatch> {
        let mut matches = Vec::new();

        for pattern in &self.patterns {
            for mat in pattern.regex.find_iter(text) {
                let matched_text = mat.as_str();

                // Apply validator if exists
                if let Some(validator) = self.validators.get(&pattern.pii_type) {
                    if !validator(matched_text) {
                        continue;
                    }
                }

                matches.push(PIIMatch {
                    pii_type: pattern.pii_type,
                    span: mat.start()..mat.end(),
                    text: matched_text.to_string(),
                    confidence: pattern.base_confidence,
                });
            }
        }

        deduplicate_overlapping(&mut matches);
        matches
    }
}

// Validators: luhn_check (credit cards), validate_ssn, validate_email
fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number.chars().filter_map(|c| c.to_digit(10)).collect();
    let sum: u32 = digits.iter().rev().enumerate().map(|(i, &d)| {
        if i % 2 == 1 { let doubled = d * 2; if doubled > 9 { doubled - 9 } else { doubled } }
        else { d }
    }).sum();
    sum % 10 == 0
}
```

### Anonymization Strategies

```rust
pub trait AnonymizationStrategy: Send + Sync {
    fn anonymize(&self, text: &str, matches: &[PIIMatch]) -> AnonymizedResult;
    fn is_reversible(&self) -> bool;
}

// Masking (Irreversible)
pub struct MaskingStrategy {
    mask_char: char,
    preserve_length: bool,
    use_type_label: bool,
}

impl AnonymizationStrategy for MaskingStrategy {
    fn anonymize(&self, text: &str, matches: &[PIIMatch]) -> AnonymizedResult {
        let mut result = text.to_string();
        for m in matches.iter().rev() {
            let replacement = if self.use_type_label {
                format!("[{}]", m.pii_type)
            } else {
                self.mask_char.to_string().repeat(m.span.len())
            };
            result.replace_range(m.span.clone(), &replacement);
        }
        AnonymizedResult { text: result, is_reversible: false, tokens: vec![] }
    }

    fn is_reversible(&self) -> bool { false }
}

// Tokenization (Reversible)
pub struct TokenizationStrategy {
    vault: Arc<TokenVault>,
    token_format: TokenFormat,
}

impl AnonymizationStrategy for TokenizationStrategy {
    fn anonymize(&self, text: &str, matches: &[PIIMatch]) -> AnonymizedResult {
        let mut result = text.to_string();
        let mut tokens = Vec::new();

        for m in matches.iter().rev() {
            let token = self.vault.create_token(&m.text, m.pii_type);
            tokens.push(token.clone());
            result.replace_range(m.span.clone(), &token);
        }

        AnonymizedResult { text: result, is_reversible: true, tokens }
    }

    fn is_reversible(&self) -> bool { true }
}

// Additional strategies: HashingStrategy, GeneralizationStrategy, DifferentialPrivacyStrategy
```

### Token Vault

```rust
pub struct TokenVault {
    storage: Arc<RwLock<HashMap<String, EncryptedEntry>>>,
    encryption: Arc<dyn EncryptionProvider>,
}

impl TokenVault {
    pub fn create_token(&self, value: &str, pii_type: PIIType) -> String {
        let token = format!("TOK_{}", Uuid::new_v4().to_string().replace("-", "")[..16].to_uppercase());
        let encrypted = self.encryption.encrypt(value.as_bytes(), &context);

        self.storage.write().insert(token.clone(), EncryptedEntry {
            encrypted_value: encrypted,
            pii_type,
            created_at: Utc::now(),
        });

        token
    }

    pub fn resolve_token(&self, token: &str) -> Result<String, AnonymizationError> {
        let entry = self.storage.read().get(token).cloned()
            .ok_or(AnonymizationError::TokenNotFound)?;
        let decrypted = self.encryption.decrypt(&entry.encrypted_value, &context)?;
        Ok(String::from_utf8(decrypted.as_slice().to_vec())?)
    }
}
```

### Anonymization Pipeline

```rust
pub struct AnonymizationPipeline {
    detectors: Vec<Arc<dyn PIIDetector>>,
    strategies: HashMap<PIIType, Arc<dyn AnonymizationStrategy>>,
    default_strategy: Arc<dyn AnonymizationStrategy>,
    confidence_threshold: f32,
}

impl AnonymizationPipeline {
    pub async fn anonymize(&self, text: &str) -> Result<AnonymizedResult, AnonymizationError> {
        // Detect PII using all detectors
        let mut all_matches = Vec::new();
        for detector in &self.detectors {
            all_matches.extend(detector.detect(text));
        }

        // Filter by confidence
        let matches: Vec<_> = all_matches.into_iter()
            .filter(|m| m.confidence >= self.confidence_threshold)
            .collect();

        // Group by strategy and apply
        let mut result = text.to_string();
        for (pii_type, type_matches) in group_by_type(&matches) {
            let strategy = self.strategies.get(&pii_type)
                .unwrap_or(&self.default_strategy);
            let anonymized = strategy.anonymize(&result, &type_matches);
            result = anonymized.text;
        }

        Ok(AnonymizedResult { text: result, .. })
    }
}
```

## 2.5 Access Control

### Authorization Engine

```rust
#[async_trait]
pub trait AuthorizationEngine: Send + Sync {
    async fn authorize(&self, request: &AuthzRequest) -> Result<AuthzDecision, AuthzError>;
}

pub struct AuthzRequest {
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
    pub context: AuthzContext,
}

pub enum AuthzDecision {
    Allow { reason: String, matched_policies: Vec<PolicyId> },
    Deny { reason: String, violations: Vec<PolicyViolation> },
}
```

### RBAC Engine

```rust
pub struct RBACEngine {
    role_store: Arc<dyn RoleStore>,
    permission_cache: Arc<RwLock<LruCache<UserId, HashSet<Permission>>>>,
}

pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub permissions: HashSet<Permission>,
    pub parent_roles: Vec<RoleId>,  // Inheritance
}

impl RBACEngine {
    pub async fn get_effective_permissions(&self, user_id: &UserId) -> Result<HashSet<Permission>, AuthzError> {
        // Check cache
        if let Some(perms) = self.permission_cache.read().get(user_id) {
            return Ok(perms.clone());
        }

        // Get role assignments and resolve inheritance
        let assignments = self.role_store.get_user_roles(user_id).await?;
        let mut permissions = HashSet::new();

        for assignment in assignments {
            let role_perms = self.resolve_role_permissions(&assignment.role_id, 0).await?;
            permissions.extend(role_perms);
        }

        // Cache result
        self.permission_cache.write().put(*user_id, permissions.clone());
        Ok(permissions)
    }

    async fn resolve_role_permissions(&self, role_id: &RoleId, depth: usize) -> Result<HashSet<Permission>, AuthzError> {
        if depth > 10 { return Err(AuthzError::CircularInheritance); }

        let role = self.role_store.get_role(role_id).await?;
        let mut permissions = role.permissions.clone();

        for parent_id in &role.parent_roles {
            let parent_perms = self.resolve_role_permissions(parent_id, depth + 1).await?;
            permissions.extend(parent_perms);
        }

        Ok(permissions)
    }
}
```

### ABAC Engine

```rust
pub struct ABACEngine {
    policy_store: Arc<dyn PolicyStore>,
}

pub struct ABACPolicy {
    pub id: PolicyId,
    pub target: PolicyTarget,
    pub rules: Vec<ABACRule>,
    pub effect: Effect,
}

pub enum Condition {
    StringEquals { attribute: String, value: String },
    StringIn { attribute: String, values: Vec<String> },
    NumericGreaterThan { attribute: String, value: f64 },
    IpInCidr { attribute: String, cidr: String },
    TimeInRange { attribute: String, start: String, end: String },
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
}

impl ABACEngine {
    pub async fn evaluate(&self, request: &AuthzRequest) -> Result<AuthzDecision, AuthzError> {
        let policies = self.policy_store.get_applicable_policies(&request.resource).await?;

        for policy in policies {
            if self.matches_target(&policy.target, request) {
                let result = self.evaluate_rules(&policy.rules, &request.context).await?;
                if result {
                    return Ok(match policy.effect {
                        Effect::Allow => AuthzDecision::Allow { .. },
                        Effect::Deny => AuthzDecision::Deny { .. },
                    });
                }
            }
        }

        // Default deny
        Ok(AuthzDecision::Deny { reason: "No matching policy".into(), violations: vec![] })
    }
}
```

## 2.6 API Layer

### REST Routes (Axum)

```rust
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Dataset endpoints
        .route("/api/v1/datasets", post(create_dataset).get(list_datasets))
        .route("/api/v1/datasets/:id", get(get_dataset).put(update_dataset).delete(delete_dataset))

        // Version endpoints
        .route("/api/v1/datasets/:id/versions", post(create_version).get(list_versions))
        .route("/api/v1/datasets/:id/versions/:version", get(get_version))

        // Record endpoints
        .route("/api/v1/datasets/:id/versions/:version/records", post(ingest_records).get(query_records))

        // Anonymization endpoints
        .route("/api/v1/anonymize", post(anonymize_text))
        .route("/api/v1/detect-pii", post(detect_pii))
        .route("/api/v1/tokenize", post(tokenize))
        .route("/api/v1/detokenize", post(detokenize))

        // Health endpoints
        .route("/health", get(health_check))
        .route("/health/ready", get(readiness))
        .route("/health/live", get(liveness))
        .route("/metrics", get(metrics))

        // Middleware stack
        .layer(from_fn(request_id_middleware))
        .layer(from_fn(tracing_middleware))
        .layer(from_fn(rate_limit_middleware))
        .layer(from_fn(auth_middleware))
        .layer(from_fn(authz_middleware))
        .with_state(state)
}
```

### Rate Limiting (Token Bucket)

```rust
pub struct RateLimiter {
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    config: RateLimitConfig,
}

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    capacity: f64,
    rate: f64,  // tokens per second
}

impl TokenBucket {
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();

        // Refill tokens
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let key = extract_rate_limit_key(&request);

    if !limiter.check_and_consume(&key) {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(request).await)
}
```

### Error Response (RFC 7807)

```rust
#[derive(Debug, Serialize)]
pub struct ApiError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub instance: String,
    pub code: String,
    pub trace_id: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<FieldError>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}
```

## 2.7 Versioning & Lineage

### Git-like Object Model

```rust
pub enum GitObject {
    Blob(BlobObject),
    Tree(TreeObject),
    Commit(CommitObject),
    Tag(TagObject),
}

pub struct CommitObject {
    pub hash: ContentHash,
    pub tree: ContentHash,
    pub parents: Vec<ContentHash>,
    pub author: CommitAuthor,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

pub struct TreeObject {
    pub hash: ContentHash,
    pub entries: Vec<TreeEntry>,
}

pub struct TreeEntry {
    pub name: String,
    pub hash: ContentHash,
    pub entry_type: EntryType,  // Blob or Tree
}
```

### Version Control Service

```rust
pub struct VersionControlService {
    object_store: Arc<dyn ObjectStore>,
    ref_store: Arc<dyn RefStore>,
}

impl VersionControlService {
    pub async fn commit(&self, dataset_id: &DatasetId, changes: StagedChanges,
        message: &str, author: &CommitAuthor) -> Result<Commit, VersioningError> {
        // Build tree from changes
        let tree = self.build_tree(&changes).await?;
        let tree_hash = self.object_store.store_tree(&tree).await?;

        // Get parent commits
        let parents = self.ref_store.get_head(dataset_id).await?.map(|h| vec![h]).unwrap_or_default();

        // Create commit
        let commit = CommitObject {
            hash: ContentHash::default(),  // Computed below
            tree: tree_hash,
            parents,
            author: author.clone(),
            message: message.to_string(),
            timestamp: Utc::now(),
        };

        let commit_hash = self.compute_commit_hash(&commit);
        self.object_store.store_commit(&commit).await?;

        // Update HEAD
        self.ref_store.update_head(dataset_id, &commit_hash).await?;

        Ok(Commit { hash: commit_hash, ..commit.into() })
    }

    pub async fn diff(&self, from: &ContentHash, to: &ContentHash) -> Result<Diff, VersioningError> {
        let from_tree = self.get_tree_for_commit(from).await?;
        let to_tree = self.get_tree_for_commit(to).await?;
        self.compute_diff(&from_tree, &to_tree).await
    }
}
```

### Data Lineage Tracking

```rust
pub struct LineageTracker {
    store: Arc<dyn LineageStore>,
}

pub struct LineageNode {
    pub id: LineageNodeId,
    pub entity: LineageEntity,
    pub created_at: DateTime<Utc>,
}

pub enum LineageEntity {
    Dataset { id: DatasetId, version: Option<VersionId> },
    Record { dataset_id: DatasetId, record_id: RecordId },
    ExternalSource { source_type: String, source_id: String },
    Transformation { name: String, version: String },
}

pub struct LineageEdge {
    pub source: LineageNodeId,
    pub target: LineageNodeId,
    pub relationship: LineageRelationship,
    pub transformation: Option<TransformationInfo>,
}

pub enum LineageRelationship {
    DerivedFrom, TransformedFrom, AnonymizedFrom,
    MergedFrom, FilteredFrom, AggregatedFrom,
}

impl LineageTracker {
    pub async fn record_derivation(&self, source: &DatasetId, target: &DatasetId,
        transformation: Option<TransformationInfo>) -> Result<(), LineageError> {
        let source_node = self.get_or_create_node(LineageEntity::Dataset { id: *source, version: None }).await?;
        let target_node = self.get_or_create_node(LineageEntity::Dataset { id: *target, version: None }).await?;

        self.store.create_edge(&LineageEdge {
            source: source_node,
            target: target_node,
            relationship: LineageRelationship::DerivedFrom,
            transformation,
        }).await
    }

    pub async fn get_upstream(&self, node_id: &LineageNodeId, depth: usize) -> Result<LineageGraph, LineageError> {
        // Traverse upstream (where did this data come from?)
        self.traverse(node_id, Direction::Upstream, depth).await
    }

    pub async fn impact_analysis(&self, node_id: &LineageNodeId) -> Result<ImpactAnalysis, LineageError> {
        let downstream = self.get_downstream(node_id, usize::MAX).await?;
        Ok(ImpactAnalysis {
            total_affected_nodes: downstream.nodes.len(),
            affected_datasets: downstream.nodes.iter().filter_map(|n| match &n.entity {
                LineageEntity::Dataset { id, .. } => Some(*id),
                _ => None,
            }).collect(),
        })
    }
}
```

## 2.8 Integration & Observability

### Event System (CloudEvents)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEvent {
    #[serde(rename = "specversion")]
    pub spec_version: String,
    pub id: String,
    pub source: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub time: DateTime<Utc>,
    #[serde(rename = "datacontenttype")]
    pub data_content_type: String,
    pub data: serde_json::Value,
}

pub enum VaultEventType {
    DatasetCreated, DatasetUpdated, DatasetDeleted,
    VersionCreated, VersionPublished,
    RecordsIngested, RecordAnonymized,
    AccessGranted, AccessDenied, PolicyViolation,
}

#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: VaultEvent) -> Result<(), EventError>;
    async fn publish_batch(&self, events: Vec<VaultEvent>) -> Result<BatchResult, EventError>;
}

pub struct KafkaEventPublisher {
    producer: FutureProducer,
    topic_prefix: String,
}

impl EventPublisher for KafkaEventPublisher {
    async fn publish(&self, event: VaultEvent) -> Result<(), EventError> {
        let topic = format!("{}.{}", self.topic_prefix, event.event_type);
        let payload = serde_json::to_string(&event)?;

        self.producer.send(
            FutureRecord::to(&topic)
                .key(&event.id)
                .payload(&payload),
            Duration::from_secs(5),
        ).await?;

        Ok(())
    }
}
```

### Webhook System

```rust
pub struct WebhookManager {
    store: Arc<dyn WebhookStore>,
    http_client: reqwest::Client,
}

pub struct Webhook {
    pub id: WebhookId,
    pub url: String,
    pub events: Vec<VaultEventType>,
    pub secret: SecureString,
    pub enabled: bool,
}

impl WebhookManager {
    pub async fn deliver(&self, webhook: &Webhook, event: &VaultEvent) -> Result<(), WebhookError> {
        let payload = serde_json::to_string(event)?;
        let signature = self.compute_signature(&payload, &webhook.secret);

        for attempt in 0..3 {
            let response = self.http_client
                .post(&webhook.url)
                .header("X-Webhook-Signature", format!("sha256={}", signature))
                .header("X-Webhook-Event", &event.event_type)
                .header("Content-Type", "application/json")
                .body(payload.clone())
                .timeout(Duration::from_secs(30))
                .send()
                .await?;

            if response.status().is_success() {
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(100 * 2u64.pow(attempt))).await;
        }

        Err(WebhookError::DeliveryFailed)
    }

    fn compute_signature(&self, payload: &str, secret: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}
```

### Observability

```rust
// Metrics
pub struct MetricsRegistry {
    pub http_requests_total: IntCounterVec,
    pub http_request_duration: HistogramVec,
    pub storage_operations_total: IntCounterVec,
    pub anonymization_duration: HistogramVec,
    pub active_connections: IntGauge,
}

lazy_static! {
    static ref HTTP_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "vault_http_requests_total",
        "Total HTTP requests",
        &["method", "endpoint", "status"]
    ).unwrap();

    static ref REQUEST_DURATION: HistogramVec = register_histogram_vec!(
        "vault_http_request_duration_seconds",
        "HTTP request duration",
        &["method", "endpoint"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    ).unwrap();
}

// Tracing
pub fn init_tracing(config: &TracingConfig) -> Result<(), TracingError> {
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(&config.endpoint))
        .with_trace_config(
            opentelemetry::sdk::trace::config()
                .with_sampler(Sampler::TraceIdRatioBased(config.sampling_ratio))
                .with_resource(Resource::new(vec![
                    KeyValue::new("service.name", "llm-data-vault"),
                ]))
        )
        .install_batch(opentelemetry::runtime::Tokio)?;

    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .with(tracing_subscriber::fmt::layer().json());

    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

// Health Checks
pub struct HealthChecker {
    checks: Vec<Box<dyn HealthCheck>>,
}

impl HealthChecker {
    pub async fn check_all(&self) -> HealthStatus {
        let results: Vec<_> = futures::future::join_all(
            self.checks.iter().map(|c| c.check())
        ).await;

        let all_healthy = results.iter().all(|r| r.status == Status::Healthy);
        HealthStatus {
            status: if all_healthy { Status::Healthy } else { Status::Degraded },
            checks: results,
        }
    }
}
```

---

# Part 3: Architecture

## 3.1 System Context

```
                                    ┌─────────────────────────────────────────┐
                                    │           LLM DevOps Platform           │
                                    └─────────────────────────────────────────┘
                                                        │
        ┌───────────────┬───────────────┬───────────────┼───────────────┐
        │               │               │               │               │
        ▼               ▼               ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ LLM-Registry │ │LLM-Policy-   │ │LLM-Analytics │ │LLM-Governance│ │   Other      │
│              │ │   Engine     │ │    -Hub      │ │  -Dashboard  │ │  Modules     │
└──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
       │                │                │                │                │
       └────────────────┴────────────────┼────────────────┴────────────────┘
                                         │
                            ┌────────────▼────────────┐
                            │                         │
                            │    LLM-DATA-VAULT       │
                            │                         │
                            │  ┌───────────────────┐  │
                            │  │     API Layer     │  │
                            │  │  (REST + gRPC)    │  │
                            │  └─────────┬─────────┘  │
                            │            │            │
                            │  ┌─────────▼─────────┐  │
                            │  │  Access Control   │  │
                            │  │  (RBAC + ABAC)    │  │
                            │  └─────────┬─────────┘  │
                            │            │            │
                            │  ┌─────────▼─────────┐  │
                            │  │   Core Services   │  │
                            │  │ ┌───┐ ┌───┐ ┌───┐ │  │
                            │  │ │Ano│ │Ver│ │Int│ │  │
                            │  │ └───┘ └───┘ └───┘ │  │
                            │  └─────────┬─────────┘  │
                            │            │            │
                            │  ┌─────────▼─────────┐  │
                            │  │    Encryption     │  │
                            │  │  (AES-256-GCM)    │  │
                            │  └─────────┬─────────┘  │
                            │            │            │
                            │  ┌─────────▼─────────┐  │
                            │  │     Storage       │  │
                            │  │(Content-Address.) │  │
                            │  └───────────────────┘  │
                            │                         │
                            └────────────┬────────────┘
                                         │
              ┌──────────────────────────┼──────────────────────────┐
              │                          │                          │
              ▼                          ▼                          ▼
     ┌────────────────┐        ┌────────────────┐        ┌────────────────┐
     │  Object Store  │        │   PostgreSQL   │        │     Redis      │
     │  (S3/GCS/Azure)│        │   (Metadata)   │        │    (Cache)     │
     └────────────────┘        └────────────────┘        └────────────────┘
```

## 3.2 Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Language** | Rust 1.75+ | Memory safety, performance |
| **Async Runtime** | Tokio | High-performance I/O |
| **REST API** | Axum | Type-safe HTTP |
| **gRPC** | Tonic | Service communication |
| **Database** | PostgreSQL | ACID metadata |
| **Object Store** | S3-compatible | Blob storage |
| **Cache** | Redis Cluster | Caching, sessions |
| **Message Queue** | Apache Kafka | Event streaming |
| **Encryption** | AES-256-GCM | Data at rest |
| **KMS** | AWS KMS / Vault | Key management |
| **Observability** | Prometheus, Jaeger | Metrics, tracing |

## 3.3 Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           API Layer                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐ │
│  │  REST API   │  │  gRPC API   │  │ Rate Limit  │  │  Validation    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────────┘ │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                        Access Control Layer                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐ │
│  │    RBAC     │  │    ABAC     │  │    OIDC     │  │   Sessions     │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────────┘ │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                         Service Layer                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐ │
│  │   Dataset   │  │Anonymization│  │  Versioning │  │  Integration   │ │
│  │   Service   │  │   Engine    │  │   Service   │  │    Layer       │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────────┘ │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                        Encryption Layer                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐ │
│  │CryptoEngine │  │  Envelope   │  │    KMS      │  │ Key Rotation   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────────┘ │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                         Storage Layer                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐ │
│  │   Object    │  │  Content    │  │   Chunk     │  │    Cache       │ │
│  │   Store     │  │ Addressable │  │  Manager    │  │   Manager      │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

## 3.4 Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Layer 1: NETWORK - WAF, DDoS protection, IP allowlisting                │
├─────────────────────────────────────────────────────────────────────────┤
│ Layer 2: API GATEWAY - Rate limiting, TLS termination, validation       │
├─────────────────────────────────────────────────────────────────────────┤
│ Layer 3: AUTHENTICATION - JWT validation, mTLS, API keys                │
├─────────────────────────────────────────────────────────────────────────┤
│ Layer 4: AUTHORIZATION - RBAC role checks, ABAC policy evaluation       │
├─────────────────────────────────────────────────────────────────────────┤
│ Layer 5: APPLICATION - Input sanitization, PII detection, audit         │
├─────────────────────────────────────────────────────────────────────────┤
│ Layer 6: DATA - Field-level encryption, tokenization                    │
├─────────────────────────────────────────────────────────────────────────┤
│ Layer 7: STORAGE - Envelope encryption (AES-256-GCM), KMS               │
└─────────────────────────────────────────────────────────────────────────┘
```

### Encryption Hierarchy

```
┌─────────────────────────────────────────┐
│        KMS (AWS/Vault/Azure)            │
│  ┌───────────────────────────────────┐  │
│  │    Master Key (CMK) - Never       │  │
│  │    leaves KMS                     │  │
│  └─────────────┬─────────────────────┘  │
└────────────────┼────────────────────────┘
                 │ Encrypts
                 ▼
┌─────────────────────────────────────────┐
│    Key Encryption Key (KEK)             │
│    Stored encrypted in DB               │
│    Rotated: 90 days                     │
└────────────────┬────────────────────────┘
                 │ Encrypts
                 ▼
┌─────────────────────────────────────────┐
│    Data Encryption Key (DEK)            │
│    Per-dataset, cached in Redis         │
│    Rotated: 30 days                     │
└────────────────┬────────────────────────┘
                 │ Encrypts
                 ▼
┌─────────────────────────────────────────┐
│           User Data                     │
│    AES-256-GCM encrypted                │
└─────────────────────────────────────────┘
```

## 3.5 Deployment Architecture

### Multi-AZ Kubernetes

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                REGION                                    │
├───────────────────────┬───────────────────────┬─────────────────────────┤
│        AZ-A           │        AZ-B           │        AZ-C             │
├───────────────────────┼───────────────────────┼─────────────────────────┤
│  ┌─────────────────┐  │  ┌─────────────────┐  │  ┌─────────────────┐    │
│  │   API Pods (3)  │  │  │   API Pods (3)  │  │  │   API Pods (3)  │    │
│  └─────────────────┘  │  └─────────────────┘  │  └─────────────────┘    │
│  ┌─────────────────┐  │  ┌─────────────────┐  │  ┌─────────────────┐    │
│  │  Worker Pods(2) │  │  │  Worker Pods(2) │  │  │  Worker Pods(2) │    │
│  └─────────────────┘  │  └─────────────────┘  │  └─────────────────┘    │
│  ┌─────────────────┐  │  ┌─────────────────┐  │  ┌─────────────────┐    │
│  │ Redis Replica   │  │  │ Redis Replica   │  │  │ Redis Primary   │    │
│  └─────────────────┘  │  └─────────────────┘  │  └─────────────────┘    │
│  ┌─────────────────┐  │  ┌─────────────────┐  │  ┌─────────────────┐    │
│  │ PG Replica      │  │  │ PG Primary      │  │  │ PG Replica      │    │
│  └─────────────────┘  │  └─────────────────┘  │  └─────────────────┘    │
└───────────────────────┴───────────────────────┴─────────────────────────┘
                                    │
                        ┌───────────▼───────────┐
                        │    Load Balancer      │
                        └───────────────────────┘
```

## 3.6 Reliability Architecture

### SLA Targets

| Metric | Target |
|--------|--------|
| Availability | 99.9% |
| Latency (p99) | < 200ms |
| Error Rate | < 0.1% |
| Throughput | 10,000 req/s |
| Data Durability | 99.999999999% |
| RTO | < 15 min |
| RPO | < 5 min |

### Resilience Patterns

**Circuit Breaker**:
- Failure threshold: 5 errors in 60s
- Open duration: 30s
- Half-open test requests: 3

**Retry with Exponential Backoff**:
- Max attempts: 3
- Initial delay: 100ms
- Max delay: 10s
- Jitter: ±25%

---

# Part 4: Refinement

## 4.1 Coding Standards

### Project Structure

```
llm-data-vault/
├── Cargo.toml                    # Workspace definition
├── crates/
│   ├── vault-core/              # Core domain types
│   ├── vault-storage/           # Storage backends
│   ├── vault-crypto/            # Encryption services
│   ├── vault-anonymize/         # PII detection
│   ├── vault-access/            # RBAC/ABAC
│   ├── vault-api/               # REST/gRPC APIs
│   ├── vault-version/           # Version control
│   └── vault-integration/       # Events/webhooks
├── tests/                       # Integration tests
└── benches/                     # Benchmarks
```

### Quality Gates

| Gate | Requirement | Enforcement |
|------|-------------|-------------|
| Compilation | Zero errors/warnings | CI block |
| Linting | Zero clippy warnings | CI block |
| Formatting | rustfmt compliant | CI block |
| Unsafe | Forbidden in libs | `#![deny(unsafe_code)]` |
| Documentation | All public APIs | `#![deny(missing_docs)]` |
| Coverage | ≥ 90% | CI block |

## 4.2 API Contracts

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/datasets` | Create dataset |
| GET | `/api/v1/datasets` | List datasets |
| GET | `/api/v1/datasets/{id}` | Get dataset |
| PUT | `/api/v1/datasets/{id}` | Update dataset |
| DELETE | `/api/v1/datasets/{id}` | Delete dataset |
| POST | `/api/v1/datasets/{id}/versions` | Create version |
| GET | `/api/v1/datasets/{id}/versions/{v}/records` | Query records |
| POST | `/api/v1/anonymize` | Anonymize data |
| POST | `/api/v1/detect-pii` | Detect PII |
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |

### Error Response Format (RFC 7807)

```json
{
  "type": "https://api.vault.example/errors/VAULT_AUTH_1001",
  "title": "Invalid Token",
  "status": 401,
  "detail": "The provided JWT token is malformed",
  "code": "VAULT_AUTH_1001",
  "trace_id": "abc123",
  "timestamp": "2025-01-01T00:00:00Z"
}
```

## 4.3 Database Schema

### Core Tables

```sql
-- Tenants (Multi-tenant isolation)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Datasets
CREATE TABLE datasets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    schema_id UUID REFERENCES schemas(id),
    encryption_key_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT datasets_name_unique UNIQUE (tenant_id, name)
);

-- Records (Partitioned)
CREATE TABLE records (
    id UUID NOT NULL,
    dataset_id UUID NOT NULL,
    version_id UUID NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    encrypted_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (dataset_id, id)
) PARTITION BY HASH (dataset_id);

-- Audit Logs (Time-partitioned)
CREATE TABLE audit_logs (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    details JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (created_at, id)
) PARTITION BY RANGE (created_at);
```

## 4.4 Error Codes

| Category | Range | Examples |
|----------|-------|----------|
| AUTH | 1000-1999 | InvalidToken, TokenExpired, MFARequired |
| AUTHZ | 2000-2999 | AccessDenied, InsufficientPermissions |
| VALID | 3000-3999 | InvalidInput, SchemaViolation |
| DATA | 4000-4999 | NotFound, Conflict, StorageError |
| CRYPTO | 5000-5999 | EncryptionFailed, KeyNotFound |
| ANON | 6000-6999 | PIIDetectionFailed, TokenizationError |
| SYS | 9000-9999 | InternalError, ServiceUnavailable |

**Total: 117 error codes**

## 4.5 Testing Strategy

### Coverage Requirements

| Category | Target |
|----------|--------|
| Overall | ≥ 90% |
| Critical paths | 100% |
| Error handling | 100% |

### Test Types

- **Unit Tests**: 70% of test effort
- **Integration Tests**: 20% with TestContainers
- **E2E Tests**: 10% full workflow
- **Security Tests**: OWASP Top 10, fuzzing
- **Performance Tests**: Criterion benchmarks, k6 load tests

## 4.6 Configuration

### Required Environment Variables

| Variable | Purpose |
|----------|---------|
| `VAULT_DATABASE_URL` | PostgreSQL connection |
| `VAULT_ENCRYPTION_MASTER_KEY` | Master encryption key |
| `VAULT_AUTH_JWT_SECRET` | JWT signing secret |

### Configuration Hierarchy

1. Default values (code)
2. Config file (TOML)
3. Environment variables
4. CLI arguments

## 4.7 Security Compliance

### Compliance Frameworks

| Framework | Key Controls |
|-----------|--------------|
| **GDPR** | Art. 5, 17, 25, 30, 32, 33 |
| **HIPAA** | Administrative, Physical, Technical safeguards |
| **SOC 2** | CC6.1-6.8, CC7.1-7.5 |
| **PCI-DSS** | Requirements 3, 4, 7, 8, 10, 12 |

### Security Checklist (125 items)

- Authentication: 20 items
- Authorization: 15 items
- Encryption: 15 items
- Input Validation: 15 items
- Audit: 10 items
- Infrastructure: 15 items
- API Security: 15 items
- Dependencies: 10 items
- Privacy: 10 items

## 4.8 Performance Requirements

### Latency Targets

| Operation | p50 | p99 |
|-----------|-----|-----|
| GET /datasets/{id} | 10ms | 50ms |
| POST /datasets | 20ms | 100ms |
| GET /records (batch) | 50ms | 200ms |
| POST /anonymize | 30ms | 150ms |

### Throughput Targets

| Component | Target |
|-----------|--------|
| API (read) | 10,000 req/s |
| API (write) | 2,000 req/s |
| Storage (read) | 1 GB/s |
| Anonymization | 10,000 records/s |

---

# Part 5: Completion

## 5.1 Cargo Workspace

```toml
[workspace]
members = [
    "crates/vault-core",
    "crates/vault-storage",
    "crates/vault-crypto",
    "crates/vault-anonymize",
    "crates/vault-access",
    "crates/vault-api",
    "crates/vault-version",
    "crates/vault-integration",
    "crates/vault-server",
]
resolver = "2"

[workspace.package]
version = "0.1.0"
edition = "2021"
rust-version = "1.75"

[workspace.dependencies]
tokio = { version = "1.35", features = ["full"] }
axum = { version = "0.7", features = ["macros"] }
tonic = { version = "0.11", features = ["tls"] }
sqlx = { version = "0.7", features = ["runtime-tokio", "postgres"] }
serde = { version = "1.0", features = ["derive"] }
thiserror = "1.0"
tracing = "0.1"

[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[profile.release]
opt-level = 3
lto = "thin"
strip = true
```

## 5.2 CI/CD Pipelines

### Main CI (.github/workflows/ci.yml)

```yaml
name: CI
on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo check --all-features

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test --all-features
      - run: cargo tarpaulin --fail-under 90

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings

  security:
    runs-on: ubuntu-latest
    steps:
      - run: cargo audit --deny warnings
```

## 5.3 Docker Configuration

### Production Dockerfile

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin vault-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/vault-server /usr/local/bin/
RUN useradd -m -u 10001 vault
USER vault
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/vault-server"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  vault-server:
    build: .
    ports: ["8080:8080", "9090:9090"]
    depends_on: [postgres, redis, localstack]

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: vault
      POSTGRES_USER: vault
      POSTGRES_PASSWORD: vault

  redis:
    image: redis:7-alpine

  localstack:
    image: localstack/localstack
    environment:
      SERVICES: s3,kms
```

## 5.4 Kubernetes Manifests

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vault-api
  template:
    spec:
      containers:
      - name: api
        image: ghcr.io/org/llm-data-vault:1.0.0
        ports:
        - containerPort: 8080
        resources:
          requests: { cpu: 500m, memory: 1Gi }
          limits: { cpu: 2000m, memory: 4Gi }
        livenessProbe:
          httpGet: { path: /health/live, port: 8080 }
        readinessProbe:
          httpGet: { path: /health/ready, port: 8080 }
```

### HPA

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: vault-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: vault-api
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## 5.5 Terraform Modules

### Module Structure

```
terraform/
├── modules/
│   ├── vpc/
│   ├── eks/
│   ├── rds/
│   ├── elasticache/
│   ├── s3/
│   └── kms/
└── environments/
    ├── dev/
    ├── staging/
    └── prod/
```

### EKS Module

```hcl
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.cluster.arn
  version  = "1.28"

  vpc_config {
    subnet_ids = var.subnet_ids
  }

  encryption_config {
    provider { key_arn = var.kms_key_arn }
    resources = ["secrets"]
  }
}

resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "general"
  instance_types  = ["m5.large"]

  scaling_config {
    desired_size = 3
    max_size     = 10
    min_size     = 2
  }
}
```

## 5.6 Implementation Roadmap

### Phase Overview

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| **1. Foundation** | 2-3 weeks | Workspace, core types, basic storage/crypto |
| **2. Core Services** | 3-4 weeks | S3, KMS, PII detection, RBAC |
| **3. API Layer** | 3-4 weeks | REST API, auth, rate limiting |
| **4. Advanced** | 4-5 weeks | NER, OIDC, versioning, gRPC |
| **5. Integration** | 3-4 weeks | Kafka, webhooks, E2E tests |
| **6. Production** | 3-4 weeks | Security audit, load testing, docs |

**Total: 18-24 weeks**

### Milestones

- **Week 3**: M1 - Core types and basic storage
- **Week 7**: M2 - Cloud services integrated
- **Week 11**: M3 - REST API functional
- **Week 16**: M4 - Full feature set
- **Week 20**: M5 - System integrated
- **Week 24**: M6 - v1.0.0 Release

### Release Criteria (v1.0.0)

- [ ] All phases complete
- [ ] Test coverage ≥ 90%
- [ ] Security audit passed
- [ ] Load testing: 10k req/s, p99 < 200ms
- [ ] Documentation complete
- [ ] Monitoring configured

---

# Appendices

## A. Glossary

| Term | Definition |
|------|------------|
| **Corpus** | Collection of text data for training/evaluating LLMs |
| **PII** | Personally Identifiable Information |
| **RBAC** | Role-Based Access Control |
| **ABAC** | Attribute-Based Access Control |
| **DEK** | Data Encryption Key |
| **KEK** | Key Encryption Key |
| **k-anonymity** | Privacy model ensuring each record is indistinguishable from k-1 others |
| **Differential Privacy** | Mathematical framework for quantifying privacy guarantees |
| **Content-Addressable** | Storage where content is addressed by its cryptographic hash |
| **Envelope Encryption** | Two-tier encryption with data keys encrypted by master keys |

## B. Reference Documents

| Document | Location |
|----------|----------|
| Specification | `plans/LLM-Data-Vault-Specification.md` |
| Pseudocode Index | `plans/pseudocode/00-index.md` |
| Architecture Index | `plans/architecture/00-index.md` |
| Refinement Index | `plans/refinement/00-index.md` |
| Completion Index | `plans/completion/00-index.md` |

## C. Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-11-27 | Initial SPARC specification |

---

*This master specification was generated using the SPARC methodology (Specification, Pseudocode, Architecture, Refinement, Completion) and consolidates 36 individual documents totaling approximately 26,665 lines of specification.*

---

**End of Master SPARC Specification**
