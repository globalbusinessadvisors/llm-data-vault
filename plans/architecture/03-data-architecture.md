# Data Architecture

**Document Version:** 1.0
**Last Updated:** 2025-11-27
**Status:** Draft
**Owner:** Architecture Team

## Executive Summary

This document defines the comprehensive data architecture for LLM-Data-Vault, an enterprise-grade system for managing training datasets with version control, encryption, and compliance features. The architecture supports multi-tenancy, horizontal scalability, and ensures data integrity, security, and auditability throughout the data lifecycle.

**Key Characteristics:**
- **Multi-tenant:** Complete data isolation between tenants
- **Versioned:** Immutable dataset versions with full lineage tracking
- **Encrypted:** Field-level and at-rest encryption with key rotation
- **Auditable:** Complete audit trail for compliance (SOC2, GDPR, HIPAA)
- **Scalable:** Petabyte-scale storage with distributed architecture

---

## 1. Data Model Overview

### 1.1 Entity Relationship Diagram

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│     Tenant      │         │       User       │         │      Role       │
├─────────────────┤         ├──────────────────┤         ├─────────────────┤
│ id: UUID    PK  │────┐    │ id: UUID     PK  │────┬────│ id: UUID    PK  │
│ name: String    │    │    │ tenant_id: UUID FK│    │    │ name: String    │
│ created_at: DT  │    │    │ email: String    │    │    │ permissions[]   │
│ settings: JSON  │    │    │ role_id: UUID  FK├────┘    │ created_at: DT  │
└─────────────────┘    │    │ created_at: DT   │         └─────────────────┘
                       │    │ last_login: DT   │
                       │    └──────────────────┘
                       │
                       │    ┌──────────────────┐         ┌─────────────────┐
                       │    │     Schema       │         │   SchemaField   │
                       │    ├──────────────────┤         ├─────────────────┤
                       │    │ id: UUID     PK  │────┬────│ id: UUID    PK  │
                       │    │ tenant_id: UUID FK│    │    │ schema_id: UUID │
                       │    │ name: String     │    │    │ name: String    │
                       │    │ version: Int     │    │    │ type: FieldType │
                       │    │ definition: JSON │    └────│ pii_type: Enum  │
                       │    │ created_at: DT   │         │ required: Bool  │
                       │    └──────────────────┘         │ validation: JSON│
                       │                                 └─────────────────┘
                       │
                       │    ┌──────────────────┐         ┌─────────────────────┐
                       ├────│     Dataset      │         │  DatasetVersion     │
                       │    ├──────────────────┤         ├─────────────────────┤
                       │    │ id: UUID     PK  │────┬────│ id: UUID        PK  │
                       │    │ tenant_id: UUID FK│    │    │ dataset_id: UUID FK │
                       │    │ name: String     │    │    │ version_num: Int    │
                       │    │ schema_id: UUID FK│    │    │ parent_version: UUID│
                       │    │ created_by: UUID │    │    │ commit_msg: String  │
                       │    │ created_at: DT   │    │    │ created_by: UUID    │
                       │    │ metadata: JSON   │    │    │ created_at: DT      │
                       │    │ tags: String[]   │    │    │ record_count: Int   │
                       │    │ retention: JSON  │    │    │ size_bytes: Int     │
                       │    │ enc_key_id: UUID │    │    │ manifest_hash: Hash │
                       │    └──────────────────┘    │    │ storage_path: String│
                       │                            │    │ metadata: JSON      │
                       │                            │    └─────────────────────┘
                       │                            │
                       │                            │    ┌─────────────────────┐
                       │                            └────│    DataRecord       │
                       │                                 ├─────────────────────┤
                       │                                 │ id: UUID        PK  │
                       │                                 │ version_id: UUID FK │
                       │                                 │ record_index: Int   │
                       │                                 │ data: JSONB         │
                       │                                 │ data_encrypted: Blob│
                       │                                 │ pii_mask: BitArray  │
                       │                                 │ created_at: DT      │
                       │                                 │ hash: Blake3Hash    │
                       │                                 └─────────────────────┘
                       │
                       │    ┌──────────────────┐         ┌─────────────────────┐
                       ├────│  RetentionPolicy │         │   PolicyRule        │
                       │    ├──────────────────┤         ├─────────────────────┤
                       │    │ id: UUID     PK  │────┬────│ id: UUID        PK  │
                       │    │ tenant_id: UUID FK│    │    │ policy_id: UUID FK  │
                       │    │ name: String     │    │    │ rule_type: Enum     │
                       │    │ duration_days: Int│   └────│ condition: JSON     │
                       │    │ action: Enum     │         │ action: Enum        │
                       │    │ created_at: DT   │         │ priority: Int       │
                       │    └──────────────────┘         └─────────────────────┘
                       │
                       │    ┌──────────────────┐         ┌─────────────────────┐
                       ├────│    AuditLog      │         │   LineageEdge       │
                       │    ├──────────────────┤         ├─────────────────────┤
                       │    │ id: UUID     PK  │         │ id: UUID        PK  │
                       │    │ tenant_id: UUID FK│        │ source_id: UUID     │
                       │    │ user_id: UUID  FK│         │ target_id: UUID     │
                       │    │ action: Enum     │         │ edge_type: Enum     │
                       │    │ resource_type: E │         │ metadata: JSON      │
                       │    │ resource_id: UUID│         │ created_at: DT      │
                       │    │ timestamp: DT    │         └─────────────────────┘
                       │    │ metadata: JSON   │
                       │    │ ip_address: IP   │         ┌─────────────────────┐
                       │    │ success: Bool    │         │   TokenMapping      │
                       │    └──────────────────┘         ├─────────────────────┤
                       │                                 │ id: UUID        PK  │
                       │    ┌──────────────────┐         │ dataset_id: UUID FK │
                       └────│  EncryptionKey   │         │ field_name: String  │
                            ├──────────────────┤         │ original_value: Hash│
                            │ id: UUID     PK  │         │ token: String       │
                            │ tenant_id: UUID FK│        │ created_at: DT      │
                            │ key_type: Enum   │         │ expires_at: DT      │
                            │ key_material: Enc│         └─────────────────────┘
                            │ kms_key_id: String│
                            │ created_at: DT   │
                            │ rotated_at: DT   │
                            │ status: Enum     │
                            └──────────────────┘
```

### 1.2 Core Entity Descriptions

| Entity | Purpose | Key Characteristics |
|--------|---------|---------------------|
| **Tenant** | Multi-tenant isolation | Root entity for all data, complete isolation |
| **Dataset** | Logical dataset container | Mutable metadata, immutable versions |
| **DatasetVersion** | Immutable snapshot | Content-addressable, versioned lineage |
| **DataRecord** | Individual training example | Field-level encryption, PII annotations |
| **Schema** | Data validation contract | Versioned, evolution support |
| **User** | Identity and access | RBAC integration, audit trail |
| **AuditLog** | Compliance and forensics | Immutable, tamper-evident |
| **EncryptionKey** | Key management | Rotation support, KMS integration |

---

## 2. Core Data Entities

### 2.1 Dataset Entity

**Purpose:** Represents a logical collection of versioned training data.

```rust
Dataset {
  // Identity
  id: DatasetId (UUID v7)              // Time-ordered UUID
  tenant_id: TenantId (UUID)           // Multi-tenant isolation
  name: String                          // Unique within tenant

  // Schema and Validation
  schema_id: SchemaId (UUID)           // Current schema version

  // Ownership and Timestamps
  created_by: UserId (UUID)            // Creator
  created_at: DateTime<Utc>            // Creation timestamp
  updated_at: DateTime<Utc>            // Last modification

  // Metadata and Classification
  description: Option<String>          // Human-readable description
  metadata: JsonValue                   // Extensible metadata
  tags: Vec<String>                    // Classification tags

  // Security and Compliance
  retention_policy_id: PolicyId        // Data retention rules
  encryption_key_id: KeyId             // Master encryption key
  classification: DataClassification   // PII, PHI, Public, etc.

  // State
  status: DatasetStatus                // Active, Archived, Deleted
  is_deleted: bool                     // Soft delete flag
  deleted_at: Option<DateTime<Utc>>    // Deletion timestamp
}

enum DatasetStatus {
  Active,
  Archived,
  Deleted,
  Migrating,
}

enum DataClassification {
  Public,
  Internal,
  Confidential,
  PII,
  PHI,
  PCI,
}
```

**Constraints:**
- `name` must be unique within `tenant_id`
- `schema_id` must reference an active schema
- `encryption_key_id` must reference an active key
- Soft deletes require `is_deleted = true` and `deleted_at` set

### 2.2 DatasetVersion Entity

**Purpose:** Immutable snapshot of a dataset at a specific point in time.

```rust
DatasetVersion {
  // Identity
  id: VersionId (UUID v7)              // Time-ordered version ID
  dataset_id: DatasetId (UUID)         // Parent dataset
  version_number: i64                  // Sequential version number

  // Version Lineage
  parent_version_id: Option<VersionId> // Previous version (null for v1)
  branch_name: Option<String>          // Branch identifier

  // Commit Information
  commit_message: String               // Description of changes
  commit_hash: Blake3Hash              // Content hash of version
  created_by: UserId                   // Version creator
  created_at: DateTime<Utc>            // Version timestamp

  // Content Statistics
  record_count: i64                    // Number of records
  size_bytes: i64                      // Total size in bytes
  chunk_count: i32                     // Number of storage chunks

  // Storage References
  manifest_hash: Blake3Hash            // Hash of manifest file
  storage_path: String                 // Object storage path

  // Metadata
  metadata: JsonValue                  // Version-specific metadata
  tags: Vec<String>                    // Version tags

  // Integrity
  checksum: Blake3Hash                 // Full dataset checksum
  signature: Option<Vec<u8>>           // Digital signature

  // State
  status: VersionStatus                // Building, Ready, Corrupted
}

enum VersionStatus {
  Building,      // Upload in progress
  Ready,         // Available for use
  Validating,    // Integrity check running
  Corrupted,     // Checksum mismatch
  Archived,      // Moved to cold storage
}

// Manifest file structure (stored in object storage)
VersionManifest {
  version_id: VersionId,
  dataset_id: DatasetId,
  schema_id: SchemaId,
  chunks: Vec<ChunkReference>,
  statistics: DatasetStatistics,
  created_at: DateTime<Utc>,
}

ChunkReference {
  chunk_id: String,              // Content hash (Blake3)
  offset: i64,                   // Record offset
  record_count: i32,             // Records in chunk
  size_bytes: i64,               // Chunk size
  compression: CompressionType,  // None, Zstd, Lz4
  checksum: Blake3Hash,          // Chunk integrity check
}
```

**Invariants:**
- Version IDs are immutable once created
- `version_number` must be unique per `dataset_id`
- `parent_version_id` must reference an existing version
- `checksum` must match recomputed hash of all chunks

### 2.3 DataRecord Entity

**Purpose:** Individual training example with field-level security.

```rust
DataRecord {
  // Identity
  id: RecordId (UUID v7)               // Unique record ID
  version_id: VersionId                // Parent version
  record_index: i64                    // Position in version

  // Data Storage (mutually exclusive)
  data: Option<JsonValue>              // Plaintext (if no PII)
  data_encrypted: Option<Vec<u8>>      // Encrypted data blob

  // PII and Security
  pii_fields: BitArray                 // Bitmap of PII fields
  encryption_context: EncryptionCtx    // DEK reference
  anonymization_token: Option<String>  // For anonymized access

  // Integrity
  hash: Blake3Hash                     // Record content hash
  created_at: DateTime<Utc>            // Insertion timestamp

  // Metadata
  source_id: Option<String>            // Original source reference
  metadata: JsonValue                  // Record-level metadata
}

EncryptionContext {
  dek_id: String,              // Data Encryption Key ID
  algorithm: String,           // AES-256-GCM
  nonce: Vec<u8>,              // Initialization vector
  auth_tag: Vec<u8>,           // Authentication tag
}

// Encrypted record format
EncryptedRecord {
  field_name: String,
  ciphertext: Vec<u8>,
  nonce: [u8; 12],
  tag: [u8; 16],
}
```

**Security Model:**
- Records with PII: `data = null`, `data_encrypted` populated
- Records without PII: `data` populated for faster access
- Field-level encryption: Each PII field encrypted separately
- Deterministic encryption for searchable fields (email, ID)

### 2.4 Schema Entity

**Purpose:** Define and validate dataset structure.

```rust
Schema {
  // Identity
  id: SchemaId (UUID)
  tenant_id: TenantId
  name: String                    // Schema name
  version: i32                    // Schema version number

  // Definition
  definition: JsonValue           // JSON Schema definition
  fields: Vec<SchemaField>,       // Structured field definitions

  // Compatibility
  parent_schema_id: Option<SchemaId>  // Previous version
  compatibility_mode: CompatMode,     // Forward, Backward, Full

  // Metadata
  description: Option<String>,
  created_by: UserId,
  created_at: DateTime<Utc>,

  // Validation
  validation_rules: Vec<ValidationRule>,

  // State
  status: SchemaStatus,           // Draft, Active, Deprecated
}

SchemaField {
  name: String,                   // Field name
  field_type: FieldType,          // Data type
  required: bool,                 // Mandatory field
  nullable: bool,                 // Allow null values
  default_value: Option<JsonValue>,

  // PII Classification
  pii_type: Option<PIIType>,      // Email, SSN, Name, etc.
  sensitivity: Sensitivity,       // Low, Medium, High, Critical

  // Validation
  validation: FieldValidation,    // Min/max, regex, enum

  // Metadata
  description: Option<String>,
  examples: Vec<JsonValue>,
}

enum FieldType {
  String { max_length: Option<usize> },
  Integer { min: Option<i64>, max: Option<i64> },
  Float { precision: Option<u8> },
  Boolean,
  DateTime,
  Array { element_type: Box<FieldType> },
  Object { schema: JsonValue },
  Enum { values: Vec<String> },
  Binary,
}

enum PIIType {
  Email,
  PhoneNumber,
  SSN,
  CreditCard,
  Name,
  Address,
  DateOfBirth,
  IPAddress,
  BiometricData,
  HealthData,
  Custom(String),
}

enum Sensitivity {
  Public,      // No restrictions
  Internal,    // Internal use only
  Confidential,// Need-to-know basis
  Restricted,  // Requires approval
  Critical,    // Highest protection
}

FieldValidation {
  min_length: Option<usize>,
  max_length: Option<usize>,
  pattern: Option<String>,        // Regex
  min_value: Option<f64>,
  max_value: Option<f64>,
  allowed_values: Option<Vec<String>>,
  custom_validator: Option<String>, // Plugin name
}
```

### 2.5 User Entity

**Purpose:** Identity, authentication, and authorization.

```rust
User {
  // Identity
  id: UserId (UUID),
  tenant_id: TenantId,

  // Authentication
  email: String,                  // Unique per tenant
  email_verified: bool,
  password_hash: Option<String>,  // bcrypt, null for SSO

  // Authorization
  role_id: RoleId,
  permissions: Vec<Permission>,   // Explicit permissions

  // Profile
  display_name: String,
  avatar_url: Option<String>,

  // Audit
  created_at: DateTime<Utc>,
  updated_at: DateTime<Utc>,
  last_login_at: Option<DateTime<Utc>>,
  last_login_ip: Option<IpAddr>,

  // State
  status: UserStatus,
  is_deleted: bool,
}

enum UserStatus {
  Active,
  Suspended,
  PendingVerification,
  Locked,
}

Role {
  id: RoleId (UUID),
  tenant_id: TenantId,
  name: String,
  description: String,
  permissions: Vec<Permission>,
  is_system_role: bool,         // Admin, ReadOnly, etc.
  created_at: DateTime<Utc>,
}

enum Permission {
  // Dataset permissions
  DatasetCreate,
  DatasetRead(DatasetId),
  DatasetUpdate(DatasetId),
  DatasetDelete(DatasetId),
  DatasetList,

  // Version permissions
  VersionCreate(DatasetId),
  VersionRead(VersionId),
  VersionDelete(VersionId),

  // Schema permissions
  SchemaCreate,
  SchemaRead,
  SchemaUpdate,

  // Admin permissions
  UserManage,
  RoleManage,
  AuditLogRead,
  KeyManage,

  // System permissions
  SystemAdmin,
}
```

### 2.6 Policy Entity

**Purpose:** Define data retention and lifecycle policies.

```rust
RetentionPolicy {
  id: PolicyId (UUID),
  tenant_id: TenantId,
  name: String,
  description: String,

  // Retention Rules
  retention_days: i32,            // Days to retain data
  action: RetentionAction,        // Delete, Archive, Anonymize

  // Conditions
  applies_to: PolicyScope,        // Specific datasets or all
  conditions: Vec<PolicyCondition>,

  // Execution
  grace_period_days: i32,         // Warning period
  enforcement_enabled: bool,
  last_run_at: Option<DateTime<Utc>>,

  // Audit
  created_by: UserId,
  created_at: DateTime<Utc>,
  updated_at: DateTime<Utc>,
}

enum RetentionAction {
  Delete,              // Permanent deletion
  Archive,             // Move to cold storage
  Anonymize,           // Strip PII
  CryptoShred,         // Delete encryption keys
}

enum PolicyScope {
  AllDatasets,
  DatasetsByTag(Vec<String>),
  SpecificDatasets(Vec<DatasetId>),
  DataClassification(DataClassification),
}

PolicyCondition {
  field: String,               // metadata.country
  operator: ConditionOp,       // Equals, Contains, etc.
  value: JsonValue,
}
```

---

## 3. Storage Architecture

### 3.1 Object Storage Layout

**Primary Storage:** S3-compatible object storage (AWS S3, MinIO, GCS)

```
{bucket}/
│
├── datasets/
│   └── {tenant_id}/
│       └── {dataset_id}/
│           ├── metadata.json                    # Dataset metadata
│           ├── schema.json                      # Current schema
│           └── versions/
│               └── {version_id}/
│                   ├── manifest.json            # Version manifest
│                   ├── metadata.json            # Version metadata
│                   └── chunks/
│                       ├── {chunk_hash_00}.zst  # Data chunks (compressed)
│                       ├── {chunk_hash_01}.zst
│                       └── {chunk_hash_nn}.zst
│
├── blobs/
│   └── {content_hash_prefix}/              # 2-char prefix for sharding
│       └── {content_hash_full}             # Content-addressable blobs
│           ├── data                        # Actual content
│           └── refs.json                   # Reference count
│
├── schemas/
│   └── {tenant_id}/
│       └── {schema_id}/
│           ├── v{version}.json             # Schema versions
│           └── validation/
│               └── {rule_id}.wasm          # Custom validators
│
├── tokens/
│   └── {tenant_id}/
│       └── {dataset_id}/
│           └── {field_name}/
│               └── {token_hash}.enc        # Anonymization tokens
│
├── keys/
│   └── {tenant_id}/
│       └── {key_id}/
│           ├── metadata.json               # Key metadata (NOT key material)
│           └── wrapped_dek.enc             # Encrypted DEK
│
├── audit/
│   └── {tenant_id}/
│       └── {year}/
│           └── {month}/
│               └── {day}/
│                   └── {hour}/
│                       └── events_{timestamp}.jsonl.zst
│
├── backups/
│   └── {tenant_id}/
│       └── {backup_id}/
│           ├── metadata.json               # Backup metadata
│           ├── database_dump.sql.zst       # PostgreSQL dump
│           └── objects_manifest.json       # List of S3 objects
│
└── temp/
    └── {tenant_id}/
        └── uploads/
            └── {upload_id}/                # Multipart upload staging
                ├── chunks/
                └── metadata.json
```

**Path Conventions:**
- All paths include `tenant_id` for multi-tenant isolation
- UUIDs use lowercase hex without hyphens for storage paths
- Chunk files use content hash as filename (content-addressable)
- Compressed files use `.zst` extension (Zstandard compression)

### 3.2 Content-Addressable Storage

**Purpose:** Deduplication and integrity verification.

```rust
// Content hash computation
fn compute_content_hash(data: &[u8]) -> Blake3Hash {
    blake3::hash(data)
}

// Blob storage structure
ContentBlob {
    hash: Blake3Hash,              // Primary identifier
    size_bytes: i64,
    compression: CompressionType,
    stored_at: DateTime<Utc>,
    storage_class: StorageClass,   // Standard, Infrequent, Archive

    // Reference tracking
    ref_count: AtomicI32,          // Number of references
    last_accessed: DateTime<Utc>,

    // Metadata
    mime_type: Option<String>,
    metadata: JsonValue,
}

// Reference table (in PostgreSQL)
ContentReference {
    blob_hash: Blake3Hash,
    version_id: VersionId,
    chunk_index: i32,
    referenced_at: DateTime<Utc>,
}
```

**Deduplication Strategy:**

1. **Upload Flow:**
   ```
   Client -> Compute Hash -> Check if Exists -> Upload if New -> Increment RefCount
   ```

2. **Deduplication Algorithm:**
   ```rust
   async fn store_chunk(data: Vec<u8>) -> Result<Blake3Hash> {
       let hash = compute_content_hash(&data);

       // Check if blob already exists
       if blob_exists(&hash).await? {
           increment_ref_count(&hash).await?;
           return Ok(hash);
       }

       // Compress and upload new blob
       let compressed = zstd::compress(&data, 3)?;
       upload_blob(&hash, &compressed).await?;
       set_ref_count(&hash, 1).await?;

       Ok(hash)
   }
   ```

3. **Reference Counting:**
   - Atomic increments on new references
   - Atomic decrements on version deletion
   - Garbage collection when `ref_count = 0`

### 3.3 Chunking Strategy

**Purpose:** Enable parallel operations and efficient incremental updates.

```rust
ChunkingConfig {
    default_chunk_size: usize = 64 * 1024 * 1024,  // 64 MB
    min_chunk_size: usize = 16 * 1024 * 1024,      // 16 MB
    max_chunk_size: usize = 256 * 1024 * 1024,     // 256 MB

    // Adaptive chunking parameters
    target_chunk_count: usize = 100,
    records_per_chunk: Option<usize> = Some(10_000),
}

// Chunking algorithm
fn chunk_records(
    records: Vec<DataRecord>,
    config: ChunkingConfig,
) -> Vec<RecordChunk> {
    let mut chunks = Vec::new();
    let mut current_chunk = Vec::new();
    let mut current_size = 0;

    for record in records {
        let record_size = estimate_size(&record);

        // Start new chunk if size or count threshold reached
        if current_size + record_size > config.default_chunk_size
            || current_chunk.len() >= config.records_per_chunk.unwrap_or(usize::MAX)
        {
            if !current_chunk.is_empty() {
                chunks.push(finalize_chunk(current_chunk, current_size));
                current_chunk = Vec::new();
                current_size = 0;
            }
        }

        current_chunk.push(record);
        current_size += record_size;
    }

    // Add remaining records
    if !current_chunk.is_empty() {
        chunks.push(finalize_chunk(current_chunk, current_size));
    }

    chunks
}

// Parallel upload
async fn upload_chunks(chunks: Vec<RecordChunk>) -> Result<Vec<Blake3Hash>> {
    let semaphore = Arc::new(Semaphore::new(10)); // Max 10 concurrent uploads

    let tasks: Vec<_> = chunks
        .into_iter()
        .map(|chunk| {
            let sem = semaphore.clone();
            tokio::spawn(async move {
                let _permit = sem.acquire().await?;
                upload_chunk(chunk).await
            })
        })
        .collect();

    futures::future::join_all(tasks).await
}
```

**Chunk Integrity Verification:**

```rust
// Verify chunk on download
async fn download_and_verify_chunk(hash: &Blake3Hash) -> Result<Vec<u8>> {
    let compressed = download_blob(hash).await?;
    let data = zstd::decompress(&compressed)?;

    // Verify integrity
    let computed_hash = compute_content_hash(&data);
    if &computed_hash != hash {
        return Err(Error::CorruptedChunk {
            expected: hash.clone(),
            actual: computed_hash,
        });
    }

    Ok(data)
}
```

### 3.4 Garbage Collection

**Purpose:** Reclaim storage from unreferenced blobs.

```rust
// Garbage collection job (runs daily)
async fn garbage_collect() -> Result<GCStats> {
    let mut stats = GCStats::default();

    // Phase 1: Mark unreferenced blobs
    let candidates = db::query!(
        "SELECT hash, ref_count, last_accessed
         FROM content_blobs
         WHERE ref_count = 0
         AND last_accessed < NOW() - INTERVAL '7 days'"
    ).fetch_all().await?;

    stats.candidates_found = candidates.len();

    // Phase 2: Grace period check (prevent race conditions)
    for candidate in candidates {
        // Re-check ref count (could have been incremented)
        let current_ref_count = get_ref_count(&candidate.hash).await?;

        if current_ref_count == 0 {
            // Delete from storage
            delete_blob(&candidate.hash).await?;

            // Delete from database
            db::query!(
                "DELETE FROM content_blobs WHERE hash = $1",
                candidate.hash
            ).execute().await?;

            stats.blobs_deleted += 1;
            stats.bytes_reclaimed += candidate.size_bytes;
        } else {
            stats.false_positives += 1;
        }
    }

    Ok(stats)
}

struct GCStats {
    candidates_found: usize,
    blobs_deleted: usize,
    bytes_reclaimed: i64,
    false_positives: usize,
}
```

---

## 4. Metadata Database Schema

### 4.1 PostgreSQL Tables

**Primary Database:** PostgreSQL 15+ with TimescaleDB extension for time-series data.

```sql
-- Tenants table
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    slug VARCHAR(100) NOT NULL UNIQUE,
    settings JSONB NOT NULL DEFAULT '{}',
    storage_quota_bytes BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_tenants_slug ON tenants(slug) WHERE NOT is_deleted;

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash VARCHAR(255),
    display_name VARCHAR(255) NOT NULL,
    avatar_url TEXT,
    role_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    last_login_ip INET,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT users_email_unique UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant_email ON users(tenant_id, email) WHERE NOT is_deleted;
CREATE INDEX idx_users_role ON users(role_id);

-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT roles_name_unique UNIQUE (tenant_id, name)
);

-- Schemas table
CREATE TABLE schemas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL,
    definition JSONB NOT NULL,
    fields JSONB NOT NULL,
    parent_schema_id UUID REFERENCES schemas(id),
    compatibility_mode VARCHAR(50) NOT NULL,
    description TEXT,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL DEFAULT 'active',

    CONSTRAINT schemas_name_version_unique UNIQUE (tenant_id, name, version)
);

CREATE INDEX idx_schemas_tenant ON schemas(tenant_id);
CREATE INDEX idx_schemas_status ON schemas(status);

-- Datasets table
CREATE TABLE datasets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    schema_id UUID NOT NULL REFERENCES schemas(id),
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}',
    tags TEXT[] NOT NULL DEFAULT '{}',
    retention_policy_id UUID,
    encryption_key_id UUID NOT NULL,
    classification VARCHAR(50) NOT NULL DEFAULT 'internal',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at TIMESTAMPTZ,

    CONSTRAINT datasets_name_unique UNIQUE (tenant_id, name)
);

CREATE INDEX idx_datasets_tenant ON datasets(tenant_id) WHERE NOT is_deleted;
CREATE INDEX idx_datasets_schema ON datasets(schema_id);
CREATE INDEX idx_datasets_tags ON datasets USING GIN(tags);
CREATE INDEX idx_datasets_status ON datasets(status);
CREATE INDEX idx_datasets_classification ON datasets(classification);

-- Dataset versions table
CREATE TABLE dataset_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dataset_id UUID NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    version_number BIGINT NOT NULL,
    parent_version_id UUID REFERENCES dataset_versions(id),
    branch_name VARCHAR(255),
    commit_message TEXT NOT NULL,
    commit_hash BYTEA NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    record_count BIGINT NOT NULL DEFAULT 0,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    chunk_count INTEGER NOT NULL DEFAULT 0,
    manifest_hash BYTEA NOT NULL,
    storage_path TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    tags TEXT[] NOT NULL DEFAULT '{}',
    checksum BYTEA NOT NULL,
    signature BYTEA,
    status VARCHAR(50) NOT NULL DEFAULT 'building',

    CONSTRAINT versions_dataset_number_unique UNIQUE (dataset_id, version_number)
);

CREATE INDEX idx_versions_dataset ON dataset_versions(dataset_id);
CREATE INDEX idx_versions_status ON dataset_versions(status);
CREATE INDEX idx_versions_created_at ON dataset_versions(created_at DESC);
CREATE INDEX idx_versions_parent ON dataset_versions(parent_version_id);

-- Data records table (partitioned by tenant_id)
CREATE TABLE data_records (
    id UUID NOT NULL,
    version_id UUID NOT NULL REFERENCES dataset_versions(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    record_index BIGINT NOT NULL,
    data JSONB,
    data_encrypted BYTEA,
    pii_fields BIT VARYING,
    encryption_context JSONB,
    anonymization_token VARCHAR(255),
    hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',

    PRIMARY KEY (tenant_id, id)
) PARTITION BY HASH (tenant_id);

-- Create 16 partitions for better parallelism
DO $$
BEGIN
    FOR i IN 0..15 LOOP
        EXECUTE format(
            'CREATE TABLE data_records_p%s PARTITION OF data_records
             FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            i, i
        );
    END LOOP;
END $$;

CREATE INDEX idx_records_version ON data_records(version_id);
CREATE INDEX idx_records_hash ON data_records(hash);
CREATE INDEX idx_records_data ON data_records USING GIN(data) WHERE data IS NOT NULL;

-- Content blobs table
CREATE TABLE content_blobs (
    hash BYTEA PRIMARY KEY,
    size_bytes BIGINT NOT NULL,
    compression VARCHAR(50) NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    storage_class VARCHAR(50) NOT NULL DEFAULT 'standard',
    ref_count INTEGER NOT NULL DEFAULT 0,
    last_accessed TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    mime_type VARCHAR(255),
    metadata JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_blobs_ref_count ON content_blobs(ref_count);
CREATE INDEX idx_blobs_last_accessed ON content_blobs(last_accessed);

-- Content references table
CREATE TABLE content_references (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    blob_hash BYTEA NOT NULL REFERENCES content_blobs(hash) ON DELETE CASCADE,
    version_id UUID NOT NULL REFERENCES dataset_versions(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    referenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT content_refs_unique UNIQUE (version_id, chunk_index)
);

CREATE INDEX idx_content_refs_blob ON content_references(blob_hash);
CREATE INDEX idx_content_refs_version ON content_references(version_id);

-- Retention policies table
CREATE TABLE retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    retention_days INTEGER NOT NULL,
    action VARCHAR(50) NOT NULL,
    applies_to JSONB NOT NULL,
    conditions JSONB NOT NULL DEFAULT '[]',
    grace_period_days INTEGER NOT NULL DEFAULT 7,
    enforcement_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT policies_name_unique UNIQUE (tenant_id, name)
);

CREATE INDEX idx_policies_tenant ON retention_policies(tenant_id);
CREATE INDEX idx_policies_enforcement ON retention_policies(enforcement_enabled);

-- Encryption keys table
CREATE TABLE encryption_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_type VARCHAR(50) NOT NULL,
    kms_key_id VARCHAR(255) NOT NULL,
    key_material_encrypted BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_keys_tenant ON encryption_keys(tenant_id);
CREATE INDEX idx_keys_status ON encryption_keys(status);

-- Audit logs table (partitioned by time using TimescaleDB)
CREATE TABLE audit_logs (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id UUID,
    metadata JSONB NOT NULL DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    duration_ms INTEGER,

    PRIMARY KEY (timestamp, id)
);

-- Convert to TimescaleDB hypertable (partitioned by time)
SELECT create_hypertable('audit_logs', 'timestamp', chunk_time_interval => INTERVAL '1 day');

CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_user ON audit_logs(user_id, timestamp DESC);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id, timestamp DESC);
CREATE INDEX idx_audit_action ON audit_logs(action, timestamp DESC);

-- Token mappings table (for anonymization)
CREATE TABLE token_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    dataset_id UUID NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    field_name VARCHAR(255) NOT NULL,
    original_value_hash BYTEA NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    access_count INTEGER NOT NULL DEFAULT 0,
    last_accessed TIMESTAMPTZ
);

CREATE INDEX idx_tokens_dataset_field ON token_mappings(dataset_id, field_name);
CREATE INDEX idx_tokens_hash ON token_mappings(original_value_hash);
CREATE INDEX idx_tokens_expires ON token_mappings(expires_at) WHERE expires_at IS NOT NULL;

-- Lineage edges table
CREATE TABLE lineage_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_version_id UUID NOT NULL REFERENCES dataset_versions(id) ON DELETE CASCADE,
    target_version_id UUID NOT NULL REFERENCES dataset_versions(id) ON DELETE CASCADE,
    edge_type VARCHAR(50) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT lineage_unique UNIQUE (source_version_id, target_version_id, edge_type)
);

CREATE INDEX idx_lineage_source ON lineage_edges(source_version_id);
CREATE INDEX idx_lineage_target ON lineage_edges(target_version_id);
CREATE INDEX idx_lineage_type ON lineage_edges(edge_type);
```

### 4.2 Database Indexes

**Query Optimization Strategy:**

1. **Primary Key Indexes:**
   - All tables use UUID primary keys
   - UUIDv7 for time-ordered insertion (better B-tree performance)

2. **Foreign Key Indexes:**
   - All foreign key columns indexed for join performance
   - Cascade deletes for data integrity

3. **Composite Indexes:**
   ```sql
   -- Multi-column indexes for common query patterns
   CREATE INDEX idx_versions_dataset_created
   ON dataset_versions(dataset_id, created_at DESC);

   CREATE INDEX idx_audit_tenant_time
   ON audit_logs(tenant_id, timestamp DESC);
   ```

4. **GIN Indexes (for JSONB and arrays):**
   ```sql
   CREATE INDEX idx_datasets_tags ON datasets USING GIN(tags);
   CREATE INDEX idx_records_data ON data_records USING GIN(data);
   CREATE INDEX idx_datasets_metadata ON datasets USING GIN(metadata);
   ```

5. **Partial Indexes:**
   ```sql
   -- Only index active records
   CREATE INDEX idx_datasets_active
   ON datasets(tenant_id) WHERE NOT is_deleted;

   -- Only index expired tokens
   CREATE INDEX idx_tokens_expired
   ON token_mappings(expires_at) WHERE expires_at < NOW();
   ```

### 4.3 Database Constraints

**Data Integrity Rules:**

```sql
-- Check constraints
ALTER TABLE datasets ADD CONSTRAINT datasets_status_check
    CHECK (status IN ('active', 'archived', 'deleted', 'migrating'));

ALTER TABLE retention_policies ADD CONSTRAINT policies_action_check
    CHECK (action IN ('delete', 'archive', 'anonymize', 'crypto_shred'));

-- Trigger for updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_datasets_updated_at
    BEFORE UPDATE ON datasets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger for soft delete validation
CREATE OR REPLACE FUNCTION validate_soft_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.is_deleted AND NEW.deleted_at IS NULL THEN
        NEW.deleted_at = NOW();
    END IF;
    IF NOT NEW.is_deleted THEN
        NEW.deleted_at = NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER validate_dataset_soft_delete
    BEFORE INSERT OR UPDATE ON datasets
    FOR EACH ROW
    EXECUTE FUNCTION validate_soft_delete();
```

---

## 5. Caching Architecture

### 5.1 Redis Cache Structure

**Cache Layers:**

```
Redis Cluster (6 nodes: 3 master, 3 replica)
│
├── Keyspace 0: Session Cache (TTL: 24h)
│   ├── session:{session_id} -> SessionData
│   └── user_sessions:{user_id} -> Set<session_id>
│
├── Keyspace 1: Permission Cache (TTL: 5m)
│   ├── perms:{user_id} -> Vec<Permission>
│   ├── role:{role_id} -> RoleData
│   └── tenant_users:{tenant_id} -> Set<user_id>
│
├── Keyspace 2: DEK Cache (TTL: 1h)
│   ├── dek:{key_id} -> EncryptedDEK (encrypted at rest)
│   └── dek_metadata:{key_id} -> KeyMetadata
│
├── Keyspace 3: Query Result Cache (TTL: 5m)
│   ├── query:{hash} -> QueryResult
│   └── dataset_stats:{dataset_id} -> Statistics
│
├── Keyspace 4: Rate Limiting (TTL: 1m)
│   ├── ratelimit:{user_id}:{endpoint} -> Counter
│   └── ratelimit_global:{ip} -> Counter
│
└── Keyspace 5: Distributed Locks (TTL: 30s)
    ├── lock:{resource_id} -> LockOwner
    └── lock_queue:{resource_id} -> Queue<LockRequest>
```

**Data Structures:**

```rust
// Session cache
SessionData {
    user_id: UserId,
    tenant_id: TenantId,
    role_id: RoleId,
    permissions: Vec<Permission>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    ip_address: IpAddr,
}

// Encrypted DEK cache
EncryptedDEK {
    key_id: KeyId,
    encrypted_material: Vec<u8>,  // Encrypted with master key
    algorithm: String,
    created_at: DateTime<Utc>,
}

// Query result cache
QueryResult {
    query_hash: String,
    result: Vec<u8>,               // Serialized result
    cached_at: DateTime<Utc>,
    ttl: i32,
}
```

### 5.2 Cache Invalidation Strategy

**Multi-Level Invalidation:**

```rust
// Event-driven invalidation
#[derive(Debug, Clone)]
enum CacheInvalidationEvent {
    UserUpdated(UserId),
    RoleUpdated(RoleId),
    DatasetUpdated(DatasetId),
    PermissionsChanged(UserId),
    KeyRotated(KeyId),
}

async fn handle_invalidation_event(event: CacheInvalidationEvent) {
    match event {
        CacheInvalidationEvent::UserUpdated(user_id) => {
            redis.del(format!("perms:{}", user_id)).await?;
            let sessions = redis.smembers(format!("user_sessions:{}", user_id)).await?;
            for session_id in sessions {
                redis.del(format!("session:{}", session_id)).await?;
            }
        }

        CacheInvalidationEvent::DatasetUpdated(dataset_id) => {
            redis.del(format!("dataset_stats:{}", dataset_id)).await?;
            // Invalidate all query caches that reference this dataset
            invalidate_query_cache_by_pattern(format!("query:*:dataset:{}", dataset_id)).await?;
        }

        CacheInvalidationEvent::KeyRotated(key_id) => {
            redis.del(format!("dek:{}", key_id)).await?;
            redis.del(format!("dek_metadata:{}", key_id)).await?;
        }

        _ => {}
    }
}
```

**Write-Through vs Write-Back:**

```rust
// Write-through: Update DB first, then cache
async fn update_dataset_write_through(
    dataset: Dataset,
) -> Result<()> {
    // 1. Update database
    db.update_dataset(&dataset).await?;

    // 2. Invalidate cache
    redis.del(format!("dataset:{}", dataset.id)).await?;

    // 3. Warm cache (optional)
    let json = serde_json::to_vec(&dataset)?;
    redis.set_ex(
        format!("dataset:{}", dataset.id),
        json,
        300, // 5 min TTL
    ).await?;

    Ok(())
}

// Write-back: Update cache first, async DB write
async fn increment_access_count_write_back(
    dataset_id: DatasetId,
) -> Result<()> {
    // 1. Increment in Redis immediately
    redis.incr(format!("access_count:{}", dataset_id)).await?;

    // 2. Queue DB update (async)
    task_queue.enqueue(Task::UpdateAccessCount {
        dataset_id,
        count: redis.get(format!("access_count:{}", dataset_id)).await?,
    }).await?;

    Ok(())
}
```

### 5.3 Cache Warming Strategy

```rust
// Pre-populate cache on application startup
async fn warm_cache_on_startup() -> Result<()> {
    // Load hot datasets (top 100 by access count)
    let hot_datasets = db::query!(
        "SELECT id, data FROM datasets
         ORDER BY access_count DESC
         LIMIT 100"
    ).fetch_all().await?;

    for dataset in hot_datasets {
        redis.set_ex(
            format!("dataset:{}", dataset.id),
            dataset.data,
            3600, // 1 hour
        ).await?;
    }

    // Load all active roles and permissions
    let roles = db::query!("SELECT * FROM roles WHERE status = 'active'")
        .fetch_all().await?;

    for role in roles {
        redis.set_ex(
            format!("role:{}", role.id),
            serde_json::to_vec(&role)?,
            300, // 5 min
        ).await?;
    }

    Ok(())
}
```

---

## 6. Data Lifecycle

### 6.1 Ingestion Pipeline

**End-to-End Flow:**

```
Client Upload -> Validation -> PII Detection -> Encryption -> Chunking -> Storage -> Indexing
```

**Detailed Pipeline:**

```rust
async fn ingest_dataset_version(
    dataset_id: DatasetId,
    records: Vec<DataRecord>,
    commit_msg: String,
) -> Result<VersionId> {
    // Phase 1: Validation
    let schema = get_dataset_schema(dataset_id).await?;
    validate_records_against_schema(&records, &schema)?;

    // Phase 2: PII Detection
    let annotated_records = detect_pii_in_records(records, &schema).await?;

    // Phase 3: Encryption
    let dek = get_or_create_dek(dataset_id).await?;
    let encrypted_records = encrypt_pii_fields(annotated_records, &dek).await?;

    // Phase 4: Chunking
    let chunks = chunk_records(encrypted_records, ChunkingConfig::default());

    // Phase 5: Storage (parallel upload)
    let chunk_hashes = upload_chunks_parallel(chunks).await?;

    // Phase 6: Create manifest
    let manifest = create_manifest(dataset_id, &chunk_hashes).await?;
    let manifest_hash = upload_manifest(&manifest).await?;

    // Phase 7: Create version record
    let version = create_version_record(
        dataset_id,
        manifest_hash,
        chunk_hashes.len(),
        commit_msg,
    ).await?;

    // Phase 8: Update indexes
    index_version_metadata(&version).await?;

    // Phase 9: Audit log
    audit_log(AuditAction::VersionCreated, &version).await?;

    Ok(version.id)
}

// PII Detection
async fn detect_pii_in_records(
    records: Vec<DataRecord>,
    schema: &Schema,
) -> Result<Vec<AnnotatedRecord>> {
    let pii_detector = PIIDetector::new();

    records
        .into_iter()
        .map(|record| {
            let mut pii_fields = BitArray::new();

            for (idx, field) in schema.fields.iter().enumerate() {
                // Check schema annotation
                if field.pii_type.is_some() {
                    pii_fields.set(idx, true);
                    continue;
                }

                // Heuristic detection
                let field_value = record.data.get(&field.name)?;
                if pii_detector.detect(field_value) {
                    pii_fields.set(idx, true);
                    log::warn!("Detected unlabeled PII in field: {}", field.name);
                }
            }

            Ok(AnnotatedRecord { record, pii_fields })
        })
        .collect()
}
```

### 6.2 Access Pipeline

**Query Flow:**

```
Client Request -> Auth -> Permission Check -> Cache Check -> Decryption -> Anonymization -> Response
```

**Implementation:**

```rust
async fn query_records(
    user: &User,
    version_id: VersionId,
    filter: RecordFilter,
) -> Result<Vec<DataRecord>> {
    // Phase 1: Authorization
    check_permission(user, Permission::VersionRead(version_id)).await?;

    // Phase 2: Cache check
    let cache_key = compute_query_cache_key(&version_id, &filter);
    if let Some(cached) = redis.get(&cache_key).await? {
        return Ok(deserialize_records(cached)?);
    }

    // Phase 3: Load manifest
    let manifest = load_manifest(version_id).await?;

    // Phase 4: Identify relevant chunks
    let chunk_indices = filter.relevant_chunks(&manifest);

    // Phase 5: Download and decrypt chunks
    let chunks = download_chunks_parallel(chunk_indices).await?;
    let dek = get_dek_from_cache_or_kms(manifest.encryption_key_id).await?;
    let decrypted = decrypt_chunks(chunks, &dek).await?;

    // Phase 6: Filter records
    let filtered = apply_filter(decrypted, &filter)?;

    // Phase 7: Anonymization (if required)
    let anonymized = if user.requires_anonymization() {
        anonymize_records(filtered, version_id).await?
    } else {
        filtered
    };

    // Phase 8: Cache result
    redis.set_ex(&cache_key, serialize_records(&anonymized)?, 300).await?;

    // Phase 9: Audit log
    audit_log(AuditAction::RecordsQueried {
        version_id,
        record_count: anonymized.len(),
    }, user).await?;

    Ok(anonymized)
}

// Anonymization
async fn anonymize_records(
    records: Vec<DataRecord>,
    version_id: VersionId,
) -> Result<Vec<DataRecord>> {
    let dataset_id = get_dataset_for_version(version_id).await?;

    for record in &mut records {
        for (field_name, value) in record.data.iter_mut() {
            if is_pii_field(field_name) {
                let token = get_or_create_token(
                    dataset_id,
                    field_name,
                    value,
                ).await?;

                *value = json!(token);
            }
        }
    }

    Ok(records)
}
```

### 6.3 Deletion Pipeline

**Deletion Types:**

1. **Soft Delete:** Mark as deleted, retain data
2. **Hard Delete:** Physically remove data
3. **Cryptographic Erasure:** Delete encryption keys

```rust
async fn delete_dataset_version(
    version_id: VersionId,
    deletion_type: DeletionType,
) -> Result<()> {
    match deletion_type {
        DeletionType::Soft => {
            // Mark as deleted in database
            db::query!(
                "UPDATE dataset_versions
                 SET status = 'deleted', deleted_at = NOW()
                 WHERE id = $1",
                version_id
            ).execute().await?;

            audit_log(AuditAction::VersionSoftDeleted, version_id).await?;
        }

        DeletionType::Hard => {
            // Get all chunk references
            let chunks = db::query!(
                "SELECT blob_hash FROM content_references
                 WHERE version_id = $1",
                version_id
            ).fetch_all().await?;

            // Decrement ref counts
            for chunk in chunks {
                decrement_ref_count(&chunk.blob_hash).await?;
            }

            // Delete references
            db::query!(
                "DELETE FROM content_references WHERE version_id = $1",
                version_id
            ).execute().await?;

            // Delete version record
            db::query!(
                "DELETE FROM dataset_versions WHERE id = $1",
                version_id
            ).execute().await?;

            // Trigger garbage collection
            schedule_garbage_collection().await?;

            audit_log(AuditAction::VersionHardDeleted, version_id).await?;
        }

        DeletionType::CryptoErasure => {
            // Delete encryption key (makes data unrecoverable)
            let key_id = get_encryption_key_for_version(version_id).await?;

            db::query!(
                "UPDATE encryption_keys
                 SET status = 'deleted', key_material_encrypted = NULL
                 WHERE id = $1",
                key_id
            ).execute().await?;

            // Invalidate DEK cache
            redis.del(format!("dek:{}", key_id)).await?;

            audit_log(AuditAction::CryptoErasure {
                version_id,
                key_id,
            }).await?;
        }
    }

    Ok(())
}

enum DeletionType {
    Soft,           // Retention policy
    Hard,           // Compliance requirement
    CryptoErasure,  // GDPR right to be forgotten
}
```

---

## 7. Data Partitioning

### 7.1 Horizontal Partitioning

**Partitioning Strategy:**

```sql
-- Partition by tenant (hash partitioning)
CREATE TABLE data_records (
    id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    ...
) PARTITION BY HASH (tenant_id);

-- Partition by time (range partitioning)
CREATE TABLE audit_logs (
    id UUID NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    ...
) PARTITION BY RANGE (timestamp);

-- Create monthly partitions for audit logs
CREATE TABLE audit_logs_2025_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE audit_logs_2025_02 PARTITION OF audit_logs
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');
```

**Partition Management:**

```rust
// Automatic partition creation
async fn ensure_audit_log_partition(date: NaiveDate) -> Result<()> {
    let partition_name = format!(
        "audit_logs_{}_{}",
        date.year(),
        date.month()
    );

    let start_date = date.with_day(1).unwrap();
    let end_date = (start_date + Duration::days(32))
        .with_day(1)
        .unwrap();

    db::execute(&format!(
        "CREATE TABLE IF NOT EXISTS {} PARTITION OF audit_logs
         FOR VALUES FROM ('{}') TO ('{}')",
        partition_name,
        start_date,
        end_date
    )).await?;

    Ok(())
}

// Partition pruning for old data
async fn prune_old_partitions(retention_days: i32) -> Result<()> {
    let cutoff_date = Utc::now().date_naive() - Duration::days(retention_days.into());

    let old_partitions = db::query!(
        "SELECT tablename FROM pg_tables
         WHERE schemaname = 'public'
         AND tablename LIKE 'audit_logs_%'"
    ).fetch_all().await?;

    for partition in old_partitions {
        if should_drop_partition(&partition.tablename, cutoff_date) {
            // Move to archive before dropping
            archive_partition(&partition.tablename).await?;

            db::execute(&format!("DROP TABLE {}", partition.tablename)).await?;
            log::info!("Dropped old partition: {}", partition.tablename);
        }
    }

    Ok(())
}
```

### 7.2 Sharding Strategy

**Shard Distribution:**

```
Shard Selection: hash(tenant_id) % num_shards

┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       v
┌─────────────────┐
│  Routing Layer  │  (Determines shard based on tenant_id)
└────────┬────────┘
         │
         ├───────────────┬───────────────┬───────────────┐
         v               v               v               v
    ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
    │ Shard 0 │     │ Shard 1 │     │ Shard 2 │     │ Shard 3 │
    │ ───────  │     │ ───────  │     │ ───────  │     │ ───────  │
    │ PG + S3 │     │ PG + S3 │     │ PG + S3 │     │ PG + S3 │
    └─────────┘     └─────────┘     └─────────┘     └─────────┘
```

**Consistent Hashing:**

```rust
struct ShardRouter {
    shards: Vec<ShardInfo>,
    ring: ConsistentHashRing,
}

impl ShardRouter {
    fn get_shard(&self, tenant_id: &TenantId) -> &ShardInfo {
        let hash = compute_tenant_hash(tenant_id);
        self.ring.get_node(hash)
    }

    fn add_shard(&mut self, shard: ShardInfo) {
        // Add with virtual nodes for better distribution
        for i in 0..150 {
            let vnode_key = format!("{}:{}", shard.id, i);
            let hash = blake3::hash(vnode_key.as_bytes());
            self.ring.add_node(hash, shard.clone());
        }

        self.shards.push(shard);
    }

    async fn rebalance(&self, new_shard: ShardInfo) -> Result<()> {
        // Calculate which tenants need to move
        let mut migrations = Vec::new();

        for tenant in self.get_all_tenants().await? {
            let old_shard = self.get_shard(&tenant.id);

            self.add_shard(new_shard.clone());
            let new_shard = self.get_shard(&tenant.id);

            if old_shard.id != new_shard.id {
                migrations.push(TenantMigration {
                    tenant_id: tenant.id,
                    from_shard: old_shard.id.clone(),
                    to_shard: new_shard.id.clone(),
                });
            }
        }

        // Execute migrations
        for migration in migrations {
            migrate_tenant(migration).await?;
        }

        Ok(())
    }
}
```

---

## 8. Backup and Recovery

### 8.1 Backup Strategy

**Backup Types:**

```
┌───────────────────────────────────────────────────────────┐
│                     Backup Schedule                        │
├───────────────────────────────────────────────────────────┤
│                                                            │
│  Daily Full Backup (12:00 AM UTC)                         │
│  ├── PostgreSQL: pg_dump with compression                 │
│  ├── Redis: RDB snapshot                                  │
│  └── S3: Manifest of all objects                          │
│                                                            │
│  Hourly Incremental Backup                                │
│  ├── PostgreSQL: WAL archiving                            │
│  └── Audit logs: Continuous streaming                     │
│                                                            │
│  Continuous Backup                                        │
│  ├── Transaction logs: Real-time streaming               │
│  └── S3: Versioning enabled                               │
│                                                            │
└───────────────────────────────────────────────────────────┘
```

**Backup Implementation:**

```rust
async fn create_full_backup() -> Result<BackupManifest> {
    let backup_id = Uuid::new_v4();
    let timestamp = Utc::now();

    // Phase 1: Backup PostgreSQL
    let pg_backup_path = format!(
        "backups/{}/{}/database.sql.zst",
        timestamp.format("%Y-%m-%d"),
        backup_id
    );

    Bash::run(&format!(
        "pg_dump -Fc {} | zstd -3 | aws s3 cp - s3://{}/{}",
        database_url(),
        backup_bucket(),
        pg_backup_path
    )).await?;

    // Phase 2: Backup Redis
    let redis_backup_path = format!(
        "backups/{}/{}/redis.rdb",
        timestamp.format("%Y-%m-%d"),
        backup_id
    );

    redis.bgsave().await?;
    upload_redis_dump(&redis_backup_path).await?;

    // Phase 3: Create S3 object manifest
    let s3_objects = list_all_s3_objects().await?;
    let manifest_path = format!(
        "backups/{}/{}/s3_manifest.json.zst",
        timestamp.format("%Y-%m-%d"),
        backup_id
    );

    upload_s3_manifest(&s3_objects, &manifest_path).await?;

    // Phase 4: Record backup metadata
    let manifest = BackupManifest {
        backup_id,
        timestamp,
        backup_type: BackupType::Full,
        database_path: pg_backup_path,
        redis_path: redis_backup_path,
        s3_manifest_path: manifest_path,
        size_bytes: calculate_backup_size().await?,
        checksum: compute_backup_checksum().await?,
    };

    save_backup_manifest(&manifest).await?;

    Ok(manifest)
}

async fn create_incremental_backup(
    last_full_backup: BackupManifest,
) -> Result<BackupManifest> {
    let backup_id = Uuid::new_v4();

    // Archive WAL files since last backup
    let wal_files = get_wal_files_since(last_full_backup.timestamp).await?;

    for wal_file in wal_files {
        let backup_path = format!(
            "backups/incremental/{}/{}.zst",
            backup_id,
            wal_file.name
        );

        compress_and_upload(&wal_file.path, &backup_path).await?;
    }

    Ok(BackupManifest {
        backup_id,
        timestamp: Utc::now(),
        backup_type: BackupType::Incremental {
            base_backup: last_full_backup.backup_id,
        },
        ..Default::default()
    })
}
```

### 8.2 Point-in-Time Recovery

**PITR Implementation:**

```rust
async fn restore_to_point_in_time(
    target_time: DateTime<Utc>,
) -> Result<()> {
    // Find the latest full backup before target time
    let base_backup = find_full_backup_before(target_time).await?;

    log::info!("Using base backup: {:?}", base_backup);

    // Restore base backup
    restore_full_backup(&base_backup).await?;

    // Apply incremental backups and WAL files
    let wal_files = get_wal_files_between(
        base_backup.timestamp,
        target_time,
    ).await?;

    for wal_file in wal_files {
        log::info!("Applying WAL file: {}", wal_file.name);
        apply_wal_file(&wal_file).await?;
    }

    // Recovery complete
    log::info!("Recovery to {} complete", target_time);

    Ok(())
}

async fn apply_wal_file(wal_file: &WalFile) -> Result<()> {
    let temp_path = download_and_decompress(wal_file).await?;

    Bash::run(&format!(
        "pg_waldump {} | psql {}",
        temp_path,
        database_url()
    )).await?;

    Ok(())
}
```

### 8.3 Disaster Recovery

**Cross-Region Replication:**

```
Primary Region (us-east-1)          Secondary Region (us-west-2)
┌─────────────────────┐              ┌─────────────────────┐
│   PostgreSQL        │              │   PostgreSQL        │
│   (Primary)         │─────────────>│   (Standby)         │
│                     │  Streaming   │                     │
└─────────────────────┘  Replication └─────────────────────┘

┌─────────────────────┐              ┌─────────────────────┐
│   S3 Bucket         │              │   S3 Bucket         │
│   (Primary)         │─────────────>│   (Replica)         │
│                     │  Cross-Region│                     │
└─────────────────────┘  Replication └─────────────────────┘

┌─────────────────────┐              ┌─────────────────────┐
│   Redis Cluster     │              │   Redis Cluster     │
│   (Active)          │─────────────>│   (Passive)         │
│                     │  Redis Sync  │                     │
└─────────────────────┘              └─────────────────────┘
```

**Disaster Recovery Procedures:**

```rust
// DR Failover
async fn failover_to_secondary_region() -> Result<()> {
    log::warn!("Initiating disaster recovery failover");

    // Step 1: Promote standby PostgreSQL to primary
    Bash::run(
        "pg_ctl promote -D /var/lib/postgresql/data"
    ).await?;

    // Step 2: Update DNS to point to secondary region
    update_dns_records(Region::UsWest2).await?;

    // Step 3: Activate secondary Redis cluster
    promote_redis_cluster().await?;

    // Step 4: Update application configuration
    update_config(Config {
        primary_region: Region::UsWest2,
        database_url: secondary_db_url(),
        s3_bucket: secondary_bucket(),
    }).await?;

    // Step 5: Verify data integrity
    verify_data_integrity().await?;

    log::info!("Failover complete. RPO: {:?}", calculate_rpo());

    Ok(())
}

// Calculate Recovery Point Objective
fn calculate_rpo() -> Duration {
    let last_replicated = get_last_replication_timestamp();
    Utc::now() - last_replicated
}
```

**SLAs:**
- **RPO (Recovery Point Objective):** < 1 hour
- **RTO (Recovery Time Objective):** < 4 hours
- **Data Durability:** 99.999999999% (11 nines)

---

## 9. Data Migration

### 9.1 Schema Evolution

**Backward Compatibility:**

```rust
// Schema version compatibility check
fn check_schema_compatibility(
    old_schema: &Schema,
    new_schema: &Schema,
) -> CompatibilityResult {
    let mut issues = Vec::new();

    // Check for removed required fields
    for old_field in &old_schema.fields {
        if old_field.required {
            if !new_schema.has_field(&old_field.name) {
                issues.push(CompatibilityIssue::RemovedRequiredField {
                    field_name: old_field.name.clone(),
                });
            }
        }
    }

    // Check for type changes
    for new_field in &new_schema.fields {
        if let Some(old_field) = old_schema.get_field(&new_field.name) {
            if !types_compatible(&old_field.field_type, &new_field.field_type) {
                issues.push(CompatibilityIssue::IncompatibleType {
                    field_name: new_field.name.clone(),
                    old_type: old_field.field_type.clone(),
                    new_type: new_field.field_type.clone(),
                });
            }
        }
    }

    if issues.is_empty() {
        CompatibilityResult::Compatible
    } else {
        CompatibilityResult::Incompatible(issues)
    }
}
```

### 9.2 Migration Scripts

**Database Migration Framework:**

```sql
-- Migration: 001_initial_schema.sql
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum VARCHAR(64) NOT NULL
);

-- Migration: 002_add_dataset_classification.sql
BEGIN;

ALTER TABLE datasets ADD COLUMN classification VARCHAR(50);
UPDATE datasets SET classification = 'internal' WHERE classification IS NULL;
ALTER TABLE datasets ALTER COLUMN classification SET NOT NULL;

INSERT INTO schema_migrations (version, name, checksum)
VALUES (2, 'add_dataset_classification', 'abc123...');

COMMIT;

-- Migration: 003_partition_data_records.sql
BEGIN;

-- Create new partitioned table
CREATE TABLE data_records_new (
    LIKE data_records INCLUDING ALL
) PARTITION BY HASH (tenant_id);

-- Create partitions
DO $$ BEGIN
    FOR i IN 0..15 LOOP
        EXECUTE format(
            'CREATE TABLE data_records_p%s PARTITION OF data_records_new
             FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            i, i
        );
    END LOOP;
END $$;

-- Migrate data
INSERT INTO data_records_new SELECT * FROM data_records;

-- Swap tables
DROP TABLE data_records;
ALTER TABLE data_records_new RENAME TO data_records;

INSERT INTO schema_migrations (version, name, checksum)
VALUES (3, 'partition_data_records', 'def456...');

COMMIT;
```

### 9.3 Rollback Procedures

```rust
async fn rollback_migration(version: i32) -> Result<()> {
    log::warn!("Rolling back migration version {}", version);

    // Load rollback script
    let rollback_script = load_rollback_script(version).await?;

    // Execute in transaction
    let mut tx = db.begin().await?;

    tx.execute(&rollback_script).await?;

    // Remove migration record
    tx.execute(
        "DELETE FROM schema_migrations WHERE version = $1",
        version
    ).await?;

    tx.commit().await?;

    log::info!("Rollback complete for version {}", version);

    Ok(())
}
```

---

## 10. Performance Considerations

### 10.1 Query Optimization

**Indexed Queries:**

```sql
-- Optimized query for listing datasets
EXPLAIN ANALYZE
SELECT d.id, d.name, d.created_at, u.display_name as creator
FROM datasets d
JOIN users u ON d.created_by = u.id
WHERE d.tenant_id = '...'
  AND d.is_deleted = FALSE
  AND d.tags && ARRAY['production']  -- GIN index on tags
ORDER BY d.created_at DESC
LIMIT 50;

-- Index Scan using idx_datasets_tenant
-- -> Nested Loop (cost=0.42..123.45 rows=50)
```

### 10.2 Scaling Considerations

**Horizontal Scaling:**
- Database: Read replicas for query distribution
- Redis: Cluster mode with 6+ nodes
- Application: Stateless API servers behind load balancer

**Vertical Scaling:**
- Database: Scale to r6g.8xlarge (256 GB RAM) for metadata
- Redis: Scale to r6g.4xlarge (128 GB RAM) for caching

---

## 11. Security Considerations

### 11.1 Encryption at Rest

**Storage Encryption:**
- S3: AES-256 server-side encryption with KMS
- PostgreSQL: Transparent Data Encryption (TDE)
- Redis: Encryption enabled for RDB and AOF files

### 11.2 Encryption in Transit

**Network Encryption:**
- TLS 1.3 for all client connections
- mTLS for service-to-service communication
- VPC peering for cross-region replication

---

## 12. Monitoring and Observability

### 12.1 Metrics

**Key Metrics:**

```
Database Metrics:
- Connection pool utilization
- Query latency (p50, p95, p99)
- Transaction rate
- Table sizes and growth rate

Storage Metrics:
- S3 object count and size
- Upload/download throughput
- Deduplication ratio
- Storage cost per tenant

Cache Metrics:
- Hit rate (target: >95%)
- Eviction rate
- Memory utilization
- Key count per namespace

Application Metrics:
- Request rate and latency
- Error rate
- Dataset version creation rate
- Active users
```

### 12.2 Alerting

**Critical Alerts:**
- Database connection pool exhausted
- Cache hit rate < 80%
- Backup failure
- Replication lag > 60 seconds
- Storage quota exceeded

---

## Appendix

### A. Glossary

| Term | Definition |
|------|------------|
| **DEK** | Data Encryption Key - symmetric key for encrypting data |
| **KEK** | Key Encryption Key - key used to encrypt DEKs |
| **WAL** | Write-Ahead Log - PostgreSQL transaction log |
| **PITR** | Point-in-Time Recovery |
| **GC** | Garbage Collection |
| **CAS** | Content-Addressable Storage |

### B. References

- PostgreSQL Partitioning: https://www.postgresql.org/docs/current/ddl-partitioning.html
- TimescaleDB: https://docs.timescale.com/
- Redis Cluster: https://redis.io/docs/management/scaling/
- AWS S3 Best Practices: https://docs.aws.amazon.com/AmazonS3/latest/userguide/

---

**Document Status:** Ready for Implementation
**Next Steps:**
1. Review with engineering team
2. Validate schema design with sample data
3. Performance testing of partitioning strategy
4. Security audit of encryption implementation
