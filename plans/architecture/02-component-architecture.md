# Component Architecture

**Document Status**: Draft
**Version**: 1.0
**Last Updated**: 2025-11-27

## Table of Contents

1. [Component Overview](#component-overview)
2. [Core Components](#core-components)
3. [Component Interaction Matrix](#component-interaction-matrix)
4. [Dependency Injection](#dependency-injection)

---

## 1. Component Overview

### 1.1 System Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           API Layer (HTTP/gRPC)                         │
└──────────────────────────┬──────────────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────────────┐
│                        Core Vault Service                               │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐                │
│  │  Dataset     │  │   Version     │  │   Query      │                │
│  │  Manager     │  │   Manager     │  │   Engine     │                │
│  └──────┬───────┘  └───────┬───────┘  └──────┬───────┘                │
└─────────┼──────────────────┼─────────────────┼────────────────────────┘
          │                  │                  │
┌─────────▼──────────────────▼─────────────────▼────────────────────────┐
│                     Component Layer                                    │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                │
│  │   Storage    │  │  Encryption  │  │ Anonymization│                │
│  │  Component   │  │  Component   │  │  Component   │                │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                │
│         │                  │                  │                         │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐                │
│  │    Access    │  │  Versioning  │  │ Integration  │                │
│  │   Control    │  │  Component   │  │  Component   │                │
│  └──────────────┘  └──────────────┘  └──────────────┘                │
└─────────────────────────────────────────────────────────────────────────┘
          │                  │                  │
┌─────────▼──────────────────▼─────────────────▼────────────────────────┐
│                      Infrastructure Layer                              │
│                                                                         │
│    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐         │
│    │   S3    │    │   KMS   │    │  Redis  │    │ Postgres│         │
│    │ Storage │    │Provider │    │  Cache  │    │   DB    │         │
│    └─────────┘    └─────────┘    └─────────┘    └─────────┘         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Responsibilities

| Component | Primary Responsibility | Key Abstractions |
|-----------|------------------------|------------------|
| **Core Vault Service** | Dataset lifecycle management | DatasetManager, VersionManager, QueryEngine |
| **Storage** | Persistent data storage & retrieval | StorageBackend, ChunkManager, CacheManager |
| **Encryption** | Data protection at rest & in transit | CryptoEngine, KeyProvider, EnvelopeEncryption |
| **Anonymization** | PII detection & transformation | PIIDetector, AnonymizationStrategy, TokenVault |
| **Access Control** | Authentication & authorization | AuthProvider, PermissionEngine, SessionManager |
| **Versioning** | Dataset version tracking | CommitManager, BranchManager, LineageTracker |
| **Integration** | External system connectivity | EventBus, WebhookManager, ModuleRegistry |

---

## 2. Core Components

### 2.1 Core Vault Service

**Purpose**: Orchestrates high-level dataset operations and coordinates between components.

#### Key Interfaces

```rust
// Dataset CRUD operations
pub trait DatasetManager: Send + Sync {
    async fn create_dataset(&self, req: CreateDatasetRequest) -> Result<Dataset>;
    async fn get_dataset(&self, id: DatasetId) -> Result<Dataset>;
    async fn update_dataset(&self, id: DatasetId, req: UpdateDatasetRequest) -> Result<Dataset>;
    async fn delete_dataset(&self, id: DatasetId) -> Result<()>;
    async fn list_datasets(&self, filter: DatasetFilter) -> Result<Vec<Dataset>>;
    async fn search_datasets(&self, query: SearchQuery) -> Result<SearchResults>;
}

// Version management
pub trait VersionManager: Send + Sync {
    async fn create_version(&self, dataset_id: DatasetId, data: DataStream) -> Result<VersionId>;
    async fn get_version(&self, version_id: VersionId) -> Result<VersionMetadata>;
    async fn list_versions(&self, dataset_id: DatasetId) -> Result<Vec<VersionMetadata>>;
    async fn compare_versions(&self, v1: VersionId, v2: VersionId) -> Result<VersionDiff>;
    async fn rollback_to_version(&self, version_id: VersionId) -> Result<()>;
}

// Query execution
pub trait QueryEngine: Send + Sync {
    async fn execute_query(&self, query: Query) -> Result<QueryResult>;
    async fn stream_query(&self, query: Query) -> Result<DataStream>;
    async fn explain_query(&self, query: Query) -> Result<QueryPlan>;
}
```

#### Internal Structure

```
CoreVaultService
├── DatasetManagerImpl
│   ├── metadata_store: MetadataStore
│   ├── storage: Arc<dyn StorageBackend>
│   ├── encryption: Arc<dyn CryptoEngine>
│   └── access_control: Arc<dyn PermissionEngine>
│
├── VersionManagerImpl
│   ├── version_store: VersionStore
│   ├── commit_manager: CommitManager
│   └── lineage_tracker: LineageTracker
│
└── QueryEngineImpl
    ├── parser: QueryParser
    ├── optimizer: QueryOptimizer
    └── executor: QueryExecutor
```

---

### 2.2 Storage Component

**Purpose**: Abstracts storage backends and manages data persistence with caching and chunking.

#### Key Interfaces

```rust
// Storage backend abstraction
pub trait StorageBackend: Send + Sync {
    async fn put(&self, key: &str, data: Bytes) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Bytes>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
    async fn copy(&self, src: &str, dst: &str) -> Result<()>;

    // Multipart upload support
    async fn start_multipart(&self, key: &str) -> Result<UploadId>;
    async fn upload_part(&self, upload_id: UploadId, part: u32, data: Bytes) -> Result<PartTag>;
    async fn complete_multipart(&self, upload_id: UploadId, parts: Vec<PartTag>) -> Result<()>;
}

// Content-addressable storage
pub trait ContentAddressableStorage: Send + Sync {
    async fn put_content(&self, content: Bytes) -> Result<ContentHash>;
    async fn get_content(&self, hash: ContentHash) -> Result<Bytes>;
    async fn has_content(&self, hash: ContentHash) -> Result<bool>;
    async fn gc_collect(&self, referenced: HashSet<ContentHash>) -> Result<GcStats>;
}

// Chunk management for large datasets
pub trait ChunkManager: Send + Sync {
    async fn chunk_data(&self, data: DataStream, strategy: ChunkStrategy) -> Result<Vec<Chunk>>;
    async fn reassemble_chunks(&self, chunk_ids: Vec<ChunkId>) -> Result<DataStream>;
    async fn deduplicate_chunks(&self, chunks: Vec<Chunk>) -> Result<Vec<ChunkRef>>;
}

// Cache layer
pub trait CacheManager: Send + Sync {
    async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>>;
    async fn set<T: Serialize>(&self, key: &str, value: &T, ttl: Duration) -> Result<()>;
    async fn invalidate(&self, key: &str) -> Result<()>;
    async fn invalidate_pattern(&self, pattern: &str) -> Result<u64>;
}
```

#### Implementations

```
StorageComponent
├── S3Backend: StorageBackend
│   ├── client: aws_sdk_s3::Client
│   ├── bucket: String
│   └── prefix: String
│
├── LocalFileBackend: StorageBackend
│   └── root_path: PathBuf
│
├── ContentAddressableStore: ContentAddressableStorage
│   ├── backend: Arc<dyn StorageBackend>
│   └── hash_algorithm: HashAlgorithm
│
├── ChunkManagerImpl: ChunkManager
│   ├── chunk_size: usize
│   ├── storage: Arc<dyn ContentAddressableStorage>
│   └── dedup_index: DedupIndex
│
└── RedisCacheManager: CacheManager
    ├── client: redis::Client
    └── key_prefix: String
```

---

### 2.3 Encryption Component

**Purpose**: Provides data encryption/decryption with key management and rotation.

#### Key Interfaces

```rust
// Core encryption operations
pub trait CryptoEngine: Send + Sync {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData>;
    async fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>>;
    async fn encrypt_stream(&self, input: DataStream) -> Result<DataStream>;
    async fn decrypt_stream(&self, input: DataStream) -> Result<DataStream>;
}

// Envelope encryption (encrypt data keys with master keys)
pub trait EnvelopeEncryption: Send + Sync {
    async fn encrypt_with_dek(&self, plaintext: &[u8]) -> Result<EnvelopeEncryptedData>;
    async fn decrypt_with_dek(&self, envelope: &EnvelopeEncryptedData) -> Result<Vec<u8>>;
    async fn rotate_dek(&self, old_envelope: &EnvelopeEncryptedData) -> Result<EnvelopeEncryptedData>;
}

// Key management service provider
pub trait KmsProvider: Send + Sync {
    async fn generate_data_key(&self, key_id: &str) -> Result<DataKey>;
    async fn encrypt_data_key(&self, key_id: &str, plaintext_key: &[u8]) -> Result<Vec<u8>>;
    async fn decrypt_data_key(&self, key_id: &str, encrypted_key: &[u8]) -> Result<Vec<u8>>;
    async fn create_master_key(&self, spec: KeySpec) -> Result<String>;
    async fn schedule_key_deletion(&self, key_id: &str, days: u32) -> Result<()>;
}

// Key rotation management
pub trait KeyRotation: Send + Sync {
    async fn rotate_dataset_key(&self, dataset_id: DatasetId) -> Result<RotationResult>;
    async fn schedule_rotation(&self, dataset_id: DatasetId, schedule: RotationSchedule) -> Result<()>;
    async fn get_rotation_status(&self, dataset_id: DatasetId) -> Result<RotationStatus>;
    async fn reencrypt_with_new_key(&self, old_key: &str, new_key: &str, data_ref: DataRef) -> Result<()>;
}
```

#### Implementations

```
EncryptionComponent
├── AesGcmCryptoEngine: CryptoEngine
│   ├── algorithm: AES-256-GCM
│   └── key_provider: Arc<dyn KmsProvider>
│
├── EnvelopeEncryptionImpl: EnvelopeEncryption
│   ├── crypto_engine: Arc<dyn CryptoEngine>
│   └── kms_provider: Arc<dyn KmsProvider>
│
├── AwsKmsProvider: KmsProvider
│   ├── client: aws_sdk_kms::Client
│   └── key_cache: KeyCache
│
├── VaultKmsProvider: KmsProvider
│   ├── client: vaultrs::Client
│   └── mount_path: String
│
└── KeyRotationManager: KeyRotation
    ├── scheduler: RotationScheduler
    ├── reencryptor: ReencryptionService
    └── audit_log: AuditLogger
```

---

### 2.4 Anonymization Component

**Purpose**: Detects and transforms PII according to privacy policies.

#### Key Interfaces

```rust
// PII detection
pub trait PIIDetector: Send + Sync {
    async fn detect(&self, data: &DataRecord) -> Result<Vec<PIIMatch>>;
    async fn detect_batch(&self, records: Vec<DataRecord>) -> Result<Vec<Vec<PIIMatch>>>;
    async fn get_confidence(&self, match_: &PIIMatch) -> f64;
    async fn classify_entity(&self, text: &str) -> Result<EntityType>;
}

// Anonymization strategies
pub trait AnonymizationStrategy: Send + Sync {
    fn name(&self) -> &str;
    async fn anonymize(&self, value: &Value, context: &AnonymizationContext) -> Result<Value>;
    async fn can_reverse(&self) -> bool;
    async fn reverse(&self, anonymized: &Value, context: &AnonymizationContext) -> Result<Value>;
}

// Token vault for reversible anonymization
pub trait TokenVault: Send + Sync {
    async fn tokenize(&self, value: &str, namespace: &str) -> Result<Token>;
    async fn detokenize(&self, token: &Token, namespace: &str) -> Result<String>;
    async fn rotate_tokens(&self, namespace: &str) -> Result<RotationResult>;
    async fn export_tokens(&self, namespace: &str, key: &EncryptionKey) -> Result<TokenExport>;
}

// Policy-based anonymization
pub trait PolicyEngine: Send + Sync {
    async fn evaluate_policy(&self, data: &DataRecord, policy: &AnonymizationPolicy) -> Result<PolicyDecision>;
    async fn apply_policy(&self, data: &DataRecord, policy: &AnonymizationPolicy) -> Result<DataRecord>;
    async fn validate_policy(&self, policy: &AnonymizationPolicy) -> Result<ValidationResult>;
}
```

#### Implementations

```
AnonymizationComponent
├── NlpPIIDetector: PIIDetector
│   ├── ner_model: NERModel (spaCy/Hugging Face)
│   ├── regex_patterns: Vec<Regex>
│   └── confidence_threshold: f64
│
├── Strategies
│   ├── RedactionStrategy: AnonymizationStrategy
│   ├── HashingStrategy: AnonymizationStrategy
│   ├── TokenizationStrategy: AnonymizationStrategy
│   ├── MaskingStrategy: AnonymizationStrategy
│   ├── GeneralizationStrategy: AnonymizationStrategy
│   └── SyntheticStrategy: AnonymizationStrategy
│
├── TokenVaultImpl: TokenVault
│   ├── token_store: TokenStore
│   ├── encryption: Arc<dyn CryptoEngine>
│   └── token_format: TokenFormat
│
└── PolicyEngineImpl: PolicyEngine
    ├── policy_store: PolicyStore
    ├── detector: Arc<dyn PIIDetector>
    └── strategies: HashMap<String, Arc<dyn AnonymizationStrategy>>
```

---

### 2.5 Access Control Component

**Purpose**: Manages authentication, authorization, and session management.

#### Key Interfaces

```rust
// Authentication provider
pub trait AuthProvider: Send + Sync {
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthToken>;
    async fn validate_token(&self, token: &str) -> Result<Claims>;
    async fn refresh_token(&self, refresh_token: &str) -> Result<AuthToken>;
    async fn revoke_token(&self, token: &str) -> Result<()>;
}

// Role-Based Access Control
pub trait RbacEngine: Send + Sync {
    async fn check_permission(&self, subject: &Subject, action: Action, resource: &Resource) -> Result<bool>;
    async fn assign_role(&self, user_id: UserId, role: Role) -> Result<()>;
    async fn revoke_role(&self, user_id: UserId, role: Role) -> Result<()>;
    async fn get_user_roles(&self, user_id: UserId) -> Result<Vec<Role>>;
    async fn get_role_permissions(&self, role: Role) -> Result<Vec<Permission>>;
}

// Attribute-Based Access Control
pub trait AbacEngine: Send + Sync {
    async fn evaluate(&self, request: &AccessRequest, policies: &[AbacPolicy]) -> Result<Decision>;
    async fn create_policy(&self, policy: AbacPolicy) -> Result<PolicyId>;
    async fn update_policy(&self, id: PolicyId, policy: AbacPolicy) -> Result<()>;
    async fn delete_policy(&self, id: PolicyId) -> Result<()>;
}

// Session management
pub trait SessionManager: Send + Sync {
    async fn create_session(&self, user_id: UserId, metadata: SessionMetadata) -> Result<SessionId>;
    async fn get_session(&self, session_id: SessionId) -> Result<Session>;
    async fn update_session(&self, session_id: SessionId, updates: SessionUpdate) -> Result<()>;
    async fn terminate_session(&self, session_id: SessionId) -> Result<()>;
    async fn cleanup_expired(&self) -> Result<u64>;
}
```

#### Implementations

```
AccessControlComponent
├── JwtAuthProvider: AuthProvider
│   ├── signing_key: SigningKey
│   ├── token_ttl: Duration
│   └── refresh_ttl: Duration
│
├── OAuthProvider: AuthProvider
│   ├── oauth_client: OAuthClient
│   ├── provider_config: ProviderConfig
│   └── token_cache: TokenCache
│
├── RbacEngineImpl: RbacEngine
│   ├── role_store: RoleStore
│   ├── permission_store: PermissionStore
│   └── cache: Arc<dyn CacheManager>
│
├── AbacEngineImpl: AbacEngine
│   ├── policy_store: PolicyStore
│   ├── evaluator: PolicyEvaluator
│   └── attribute_provider: AttributeProvider
│
└── RedisSessionManager: SessionManager
    ├── redis: Arc<dyn CacheManager>
    ├── session_ttl: Duration
    └── cleanup_interval: Duration
```

---

### 2.6 Versioning Component

**Purpose**: Provides Git-like versioning with branching and lineage tracking.

#### Key Interfaces

```rust
// Git-like commit management
pub trait CommitManager: Send + Sync {
    async fn create_commit(&self, parent: Option<CommitId>, tree: TreeId, message: &str) -> Result<CommitId>;
    async fn get_commit(&self, id: CommitId) -> Result<Commit>;
    async fn list_commits(&self, branch: BranchId, limit: usize) -> Result<Vec<Commit>>;
    async fn get_commit_tree(&self, id: CommitId) -> Result<Tree>;
    async fn diff_commits(&self, from: CommitId, to: CommitId) -> Result<CommitDiff>;
}

// Branch management
pub trait BranchManager: Send + Sync {
    async fn create_branch(&self, name: &str, from: CommitId) -> Result<BranchId>;
    async fn get_branch(&self, id: BranchId) -> Result<Branch>;
    async fn update_branch(&self, id: BranchId, commit: CommitId) -> Result<()>;
    async fn delete_branch(&self, id: BranchId) -> Result<()>;
    async fn merge_branches(&self, source: BranchId, target: BranchId, strategy: MergeStrategy) -> Result<CommitId>;
    async fn list_branches(&self, dataset_id: DatasetId) -> Result<Vec<Branch>>;
}

// Data lineage tracking
pub trait LineageTracker: Send + Sync {
    async fn record_lineage(&self, event: LineageEvent) -> Result<()>;
    async fn get_upstream(&self, dataset_id: DatasetId) -> Result<Vec<LineageNode>>;
    async fn get_downstream(&self, dataset_id: DatasetId) -> Result<Vec<LineageNode>>;
    async fn trace_provenance(&self, data_ref: DataRef) -> Result<ProvenanceGraph>;
    async fn impact_analysis(&self, dataset_id: DatasetId) -> Result<ImpactReport>;
}

// Object storage (Git-like)
pub trait ObjectStore: Send + Sync {
    async fn put_object(&self, obj: Object) -> Result<ObjectId>;
    async fn get_object(&self, id: ObjectId) -> Result<Object>;
    async fn exists(&self, id: ObjectId) -> Result<bool>;
}
```

#### Implementations

```
VersioningComponent
├── CommitManagerImpl: CommitManager
│   ├── object_store: Arc<dyn ObjectStore>
│   ├── tree_builder: TreeBuilder
│   └── diff_engine: DiffEngine
│
├── BranchManagerImpl: BranchManager
│   ├── branch_store: BranchStore
│   ├── commit_manager: Arc<dyn CommitManager>
│   └── merge_strategies: Vec<Box<dyn MergeStrategy>>
│
├── LineageTrackerImpl: LineageTracker
│   ├── lineage_graph: LineageGraph
│   ├── event_store: EventStore
│   └── graph_db: GraphDatabase
│
└── ContentAddressableObjectStore: ObjectStore
    ├── cas: Arc<dyn ContentAddressableStorage>
    └── compression: CompressionAlgorithm
```

---

### 2.7 Integration Component

**Purpose**: Enables external system integration via events, webhooks, and modules.

#### Key Interfaces

```rust
// Event bus for publish/subscribe
pub trait EventBus: Send + Sync {
    async fn publish(&self, event: Event) -> Result<()>;
    async fn subscribe(&self, pattern: EventPattern, handler: EventHandler) -> Result<SubscriptionId>;
    async fn unsubscribe(&self, id: SubscriptionId) -> Result<()>;
    async fn replay_events(&self, from: Timestamp, to: Timestamp) -> Result<Vec<Event>>;
}

// Webhook management
pub trait WebhookManager: Send + Sync {
    async fn register_webhook(&self, config: WebhookConfig) -> Result<WebhookId>;
    async fn trigger_webhook(&self, id: WebhookId, event: Event) -> Result<()>;
    async fn get_webhook_status(&self, id: WebhookId) -> Result<WebhookStatus>;
    async fn delete_webhook(&self, id: WebhookId) -> Result<()>;
    async fn retry_failed(&self, id: WebhookId) -> Result<()>;
}

// Plugin/module system
pub trait ModuleRegistry: Send + Sync {
    async fn register_module(&self, module: Box<dyn Module>) -> Result<ModuleId>;
    async fn unregister_module(&self, id: ModuleId) -> Result<()>;
    async fn get_module(&self, id: ModuleId) -> Result<Arc<dyn Module>>;
    async fn list_modules(&self) -> Result<Vec<ModuleInfo>>;
}

// External module interface
pub trait Module: Send + Sync {
    fn info(&self) -> ModuleInfo;
    async fn initialize(&mut self, context: &ModuleContext) -> Result<()>;
    async fn handle_event(&self, event: Event) -> Result<()>;
    async fn shutdown(&self) -> Result<()>;
}
```

#### Implementations

```
IntegrationComponent
├── InMemoryEventBus: EventBus
│   ├── subscribers: HashMap<EventPattern, Vec<EventHandler>>
│   └── event_log: EventLog
│
├── RedisEventBus: EventBus
│   ├── client: redis::Client
│   └── channel_prefix: String
│
├── WebhookManagerImpl: WebhookManager
│   ├── webhook_store: WebhookStore
│   ├── http_client: HttpClient
│   ├── retry_policy: RetryPolicy
│   └── delivery_queue: DeliveryQueue
│
└── ModuleRegistryImpl: ModuleRegistry
    ├── modules: HashMap<ModuleId, Arc<dyn Module>>
    └── lifecycle_manager: LifecycleManager
```

---

## 3. Component Interaction Matrix

### 3.1 Direct Dependencies

| Component | Storage | Encryption | Anonymization | Access Control | Versioning | Integration |
|-----------|---------|------------|---------------|----------------|------------|-------------|
| **Core Vault Service** | X | X | X | X | X | X |
| **Storage** | - | O | - | - | - | O |
| **Encryption** | - | - | - | - | - | - |
| **Anonymization** | - | O | - | - | - | O |
| **Access Control** | O | - | - | - | - | O |
| **Versioning** | X | - | - | O | - | O |
| **Integration** | - | - | - | O | - | - |

**Legend:**
- `X` = Strong dependency (component requires this for core functionality)
- `O` = Weak dependency (component may use this for enhanced features)
- `-` = No direct dependency

### 3.2 Data Flow Interactions

```
Dataset Creation Flow:
┌─────────────┐
│    User     │
└──────┬──────┘
       │ 1. Create Dataset
       ▼
┌─────────────────────┐
│  Core Vault Service │
└──────┬──────────────┘
       │ 2. Check Permissions
       ▼
┌─────────────────────┐
│  Access Control     │
└──────┬──────────────┘
       │ 3. Authorized
       ▼
┌─────────────────────┐
│  Core Vault Service │────────────────┐
└──────┬──────────────┘                │
       │ 4. Detect PII                 │ 5. Create Initial Version
       ▼                                ▼
┌─────────────────────┐         ┌─────────────────────┐
│  Anonymization      │         │    Versioning       │
└──────┬──────────────┘         └──────┬──────────────┘
       │ 6. Anonymized Data            │ 7. Commit Created
       ▼                                ▼
┌─────────────────────┐         ┌─────────────────────┐
│   Encryption        │         │      Storage        │
└──────┬──────────────┘         └──────┬──────────────┘
       │ 8. Encrypted Chunks            │ 9. Chunks Stored
       ▼                                ▼
┌─────────────────────┐         ┌─────────────────────┐
│     Storage         │         │    Integration      │
└──────┬──────────────┘         └──────┬──────────────┘
       │                                │ 10. Publish Event
       └────────────────┬───────────────┘
                        ▼
                 ┌─────────────┐
                 │   Success   │
                 └─────────────┘
```

### 3.3 Event-Driven Interactions

| Event Type | Publisher | Subscribers |
|------------|-----------|-------------|
| `DatasetCreated` | Core Vault Service | Integration, Versioning, Access Control |
| `DatasetUpdated` | Core Vault Service | Integration, Versioning, Anonymization |
| `DatasetDeleted` | Core Vault Service | Integration, Storage (cleanup), Access Control |
| `VersionCreated` | Versioning | Integration, Storage |
| `KeyRotated` | Encryption | Storage (re-encrypt), Integration |
| `PIIDetected` | Anonymization | Integration, Audit Log |
| `AccessDenied` | Access Control | Integration, Audit Log |
| `CacheMiss` | Storage | Integration (metrics) |
| `WebhookFailed` | Integration | Integration (retry queue) |

---

## 4. Dependency Injection

### 4.1 Service Container Pattern

```rust
pub struct ServiceContainer {
    // Infrastructure
    storage_backend: Arc<dyn StorageBackend>,
    cache_manager: Arc<dyn CacheManager>,
    event_bus: Arc<dyn EventBus>,

    // Security
    crypto_engine: Arc<dyn CryptoEngine>,
    kms_provider: Arc<dyn KmsProvider>,
    auth_provider: Arc<dyn AuthProvider>,

    // Core components
    dataset_manager: Arc<dyn DatasetManager>,
    version_manager: Arc<dyn VersionManager>,
    query_engine: Arc<dyn QueryEngine>,

    // Specialized components
    pii_detector: Arc<dyn PIIDetector>,
    token_vault: Arc<dyn TokenVault>,
    policy_engine: Arc<dyn PolicyEngine>,
    rbac_engine: Arc<dyn RbacEngine>,
    lineage_tracker: Arc<dyn LineageTracker>,
}

impl ServiceContainer {
    pub fn new(config: &Config) -> Result<Self> {
        // Build from configuration
        let storage_backend = Self::build_storage(config)?;
        let cache_manager = Self::build_cache(config)?;
        let event_bus = Self::build_event_bus(config)?;

        let kms_provider = Self::build_kms(config)?;
        let crypto_engine = Self::build_crypto(config, kms_provider.clone())?;
        let auth_provider = Self::build_auth(config)?;

        // Components with dependencies
        let pii_detector = Self::build_pii_detector(config)?;
        let token_vault = Self::build_token_vault(config, crypto_engine.clone())?;
        let policy_engine = Self::build_policy_engine(config, pii_detector.clone())?;

        let rbac_engine = Self::build_rbac(config, cache_manager.clone())?;
        let lineage_tracker = Self::build_lineage(config)?;

        let version_manager = Self::build_version_manager(
            config,
            storage_backend.clone(),
            lineage_tracker.clone()
        )?;

        let dataset_manager = Self::build_dataset_manager(
            config,
            storage_backend.clone(),
            crypto_engine.clone(),
            policy_engine.clone(),
            rbac_engine.clone(),
            version_manager.clone()
        )?;

        let query_engine = Self::build_query_engine(
            config,
            storage_backend.clone(),
            rbac_engine.clone()
        )?;

        Ok(Self {
            storage_backend,
            cache_manager,
            event_bus,
            crypto_engine,
            kms_provider,
            auth_provider,
            dataset_manager,
            version_manager,
            query_engine,
            pii_detector,
            token_vault,
            policy_engine,
            rbac_engine,
            lineage_tracker,
        })
    }

    // Getters for each service
    pub fn dataset_manager(&self) -> Arc<dyn DatasetManager> {
        self.dataset_manager.clone()
    }

    pub fn version_manager(&self) -> Arc<dyn VersionManager> {
        self.version_manager.clone()
    }

    // ... additional getters
}
```

### 4.2 Builder Pattern for Testing

```rust
pub struct ServiceContainerBuilder {
    storage: Option<Arc<dyn StorageBackend>>,
    cache: Option<Arc<dyn CacheManager>>,
    crypto: Option<Arc<dyn CryptoEngine>>,
    auth: Option<Arc<dyn AuthProvider>>,
    // ... other components
}

impl ServiceContainerBuilder {
    pub fn new() -> Self {
        Self {
            storage: None,
            cache: None,
            crypto: None,
            auth: None,
        }
    }

    pub fn with_storage(mut self, storage: Arc<dyn StorageBackend>) -> Self {
        self.storage = Some(storage);
        self
    }

    pub fn with_mock_storage(self) -> Self {
        self.with_storage(Arc::new(MockStorageBackend::new()))
    }

    pub fn with_cache(mut self, cache: Arc<dyn CacheManager>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_crypto(mut self, crypto: Arc<dyn CryptoEngine>) -> Self {
        self.crypto = Some(crypto);
        self
    }

    pub fn build(self) -> Result<ServiceContainer> {
        // Use provided implementations or create defaults
        let storage = self.storage.unwrap_or_else(|| {
            Arc::new(InMemoryStorageBackend::new())
        });

        let cache = self.cache.unwrap_or_else(|| {
            Arc::new(InMemoryCacheManager::new())
        });

        // ... build complete container

        Ok(ServiceContainer {
            storage_backend: storage,
            cache_manager: cache,
            // ... other components
        })
    }
}

// Usage in tests
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dataset_creation() {
        let container = ServiceContainerBuilder::new()
            .with_mock_storage()
            .with_cache(Arc::new(InMemoryCacheManager::new()))
            .build()
            .unwrap();

        let dataset_manager = container.dataset_manager();

        // Test dataset creation
        let result = dataset_manager.create_dataset(
            CreateDatasetRequest {
                name: "test-dataset".to_string(),
                // ...
            }
        ).await;

        assert!(result.is_ok());
    }
}
```

### 4.3 Mock Implementations for Testing

```rust
// Mock storage backend
pub struct MockStorageBackend {
    data: Arc<RwLock<HashMap<String, Bytes>>>,
    calls: Arc<RwLock<Vec<StorageCall>>>,
}

#[async_trait]
impl StorageBackend for MockStorageBackend {
    async fn put(&self, key: &str, data: Bytes) -> Result<()> {
        self.calls.write().await.push(StorageCall::Put(key.to_string()));
        self.data.write().await.insert(key.to_string(), data);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        self.calls.write().await.push(StorageCall::Get(key.to_string()));
        self.data.read().await
            .get(key)
            .cloned()
            .ok_or_else(|| anyhow!("Key not found"))
    }

    // ... other methods
}

impl MockStorageBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            calls: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn assert_put_called(&self, key: &str) {
        let calls = self.calls.read().await;
        assert!(calls.iter().any(|c| matches!(c, StorageCall::Put(k) if k == key)));
    }

    pub async fn get_call_count(&self) -> usize {
        self.calls.read().await.len()
    }
}

// Mock crypto engine
pub struct MockCryptoEngine {
    encryption_count: Arc<AtomicUsize>,
}

#[async_trait]
impl CryptoEngine for MockCryptoEngine {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        self.encryption_count.fetch_add(1, Ordering::SeqCst);

        // Simple mock: just wrap the plaintext
        Ok(EncryptedData {
            ciphertext: plaintext.to_vec(),
            algorithm: "MOCK-AES-256-GCM".to_string(),
            key_id: "mock-key-id".to_string(),
            nonce: vec![0u8; 12],
        })
    }

    async fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        // Simple mock: just unwrap
        Ok(encrypted.ciphertext.clone())
    }

    // ... other methods
}

impl MockCryptoEngine {
    pub fn new() -> Self {
        Self {
            encryption_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn get_encryption_count(&self) -> usize {
        self.encryption_count.load(Ordering::SeqCst)
    }
}
```

### 4.4 Configuration-Driven Assembly

```rust
#[derive(Deserialize)]
pub struct ComponentConfig {
    pub storage: StorageConfig,
    pub encryption: EncryptionConfig,
    pub cache: CacheConfig,
    pub auth: AuthConfig,
    pub anonymization: AnonymizationConfig,
}

#[derive(Deserialize)]
pub struct StorageConfig {
    pub backend: String, // "s3", "local", "azure"
    pub s3: Option<S3Config>,
    pub local: Option<LocalConfig>,
}

#[derive(Deserialize)]
pub struct EncryptionConfig {
    pub kms_provider: String, // "aws", "vault", "local"
    pub algorithm: String,     // "AES-256-GCM"
    pub aws_kms: Option<AwsKmsConfig>,
}

impl ServiceContainer {
    fn build_storage(config: &ComponentConfig) -> Result<Arc<dyn StorageBackend>> {
        match config.storage.backend.as_str() {
            "s3" => {
                let s3_config = config.storage.s3.as_ref()
                    .ok_or_else(|| anyhow!("S3 config required"))?;
                Ok(Arc::new(S3Backend::new(s3_config)?))
            }
            "local" => {
                let local_config = config.storage.local.as_ref()
                    .ok_or_else(|| anyhow!("Local config required"))?;
                Ok(Arc::new(LocalFileBackend::new(local_config)?))
            }
            _ => Err(anyhow!("Unknown storage backend: {}", config.storage.backend))
        }
    }

    fn build_crypto(
        config: &ComponentConfig,
        kms: Arc<dyn KmsProvider>
    ) -> Result<Arc<dyn CryptoEngine>> {
        match config.encryption.algorithm.as_str() {
            "AES-256-GCM" => Ok(Arc::new(AesGcmCryptoEngine::new(kms)?)),
            _ => Err(anyhow!("Unknown encryption algorithm: {}", config.encryption.algorithm))
        }
    }

    // ... other builders
}
```

---

## Summary

This document defines the component architecture for LLM-Data-Vault:

1. **Seven Core Components**: Each with clear responsibilities and well-defined interfaces
   - Core Vault Service: High-level orchestration
   - Storage: Persistent data with caching and chunking
   - Encryption: Data protection and key management
   - Anonymization: PII detection and transformation
   - Access Control: Authentication and authorization
   - Versioning: Git-like version control
   - Integration: External system connectivity

2. **Component Interactions**: Clear dependency relationships and event-driven communication patterns

3. **Dependency Injection**: Service container pattern enables:
   - Clean separation of concerns
   - Easy testing with mock implementations
   - Configuration-driven assembly
   - Flexible component replacement

All components follow trait-based abstractions enabling multiple implementations and comprehensive testing strategies.
