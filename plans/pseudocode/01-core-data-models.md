# LLM-Data-Vault Pseudocode: Core Data Models

**Document:** 01-core-data-models.md
**Version:** 1.0.0
**Phase:** SPARC - Pseudocode
**Last Updated:** 2025-11-27

---

## Overview

This document defines the core data models and type definitions for LLM-Data-Vault. All types are designed to be:
- Type-safe with compile-time guarantees
- Serialization-ready (serde compatible)
- Zero-copy where possible
- Production-ready with validation

---

## Module Structure

```rust
// src/models/mod.rs
pub mod common;
pub mod dataset;
pub mod record;
pub mod corpus;
pub mod user;
pub mod audit;
pub mod policy;
pub mod error;
```

---

## 1. Common Types

```rust
// src/models/common.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// ID Types (Newtype Pattern for Type Safety)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DatasetId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VersionId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecordId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CorpusId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrganizationId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WorkspaceId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditEventId(pub Uuid);

impl DatasetId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

// Similar impl for all ID types...

// ============================================================================
// Checksum Types
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "algorithm", content = "value")]
pub enum Checksum {
    Sha256([u8; 32]),
    Sha512([u8; 64]),
    Blake3([u8; 32]),
}

impl Checksum {
    pub fn sha256(data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self::Sha256(bytes)
    }

    pub fn verify(&self, data: &[u8]) -> bool {
        match self {
            Checksum::Sha256(expected) => {
                let computed = Self::sha256(data);
                matches!(computed, Checksum::Sha256(ref h) if h == expected)
            }
            // Similar for other algorithms
            _ => unimplemented!()
        }
    }

    pub fn to_hex(&self) -> String {
        match self {
            Checksum::Sha256(bytes) => hex::encode(bytes),
            Checksum::Sha512(bytes) => hex::encode(bytes),
            Checksum::Blake3(bytes) => hex::encode(bytes),
        }
    }
}

// ============================================================================
// Content Hash (for Content-Addressable Storage)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentHash {
    pub algorithm: HashAlgorithm,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

impl ContentHash {
    pub fn compute(data: &[u8], algorithm: HashAlgorithm) -> Self {
        let bytes = match algorithm {
            HashAlgorithm::Sha256 => {
                use sha2::{Sha256, Digest};
                Sha256::digest(data).to_vec()
            }
            HashAlgorithm::Blake3 => {
                blake3::hash(data).as_bytes().to_vec()
            }
        };
        Self { algorithm, bytes }
    }

    pub fn to_string(&self) -> String {
        format!("{}:{}", self.algorithm.prefix(), hex::encode(&self.bytes))
    }
}

// ============================================================================
// Timestamps
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }

    pub fn from_unix_millis(millis: i64) -> Self {
        Self(DateTime::from_timestamp_millis(millis).unwrap_or_default())
    }

    pub fn as_datetime(&self) -> DateTime<Utc> {
        self.0
    }
}

// ============================================================================
// Byte Size
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub const KB: u64 = 1024;
    pub const MB: u64 = 1024 * 1024;
    pub const GB: u64 = 1024 * 1024 * 1024;
    pub const TB: u64 = 1024 * 1024 * 1024 * 1024;

    pub fn bytes(n: u64) -> Self { Self(n) }
    pub fn kilobytes(n: u64) -> Self { Self(n * Self::KB) }
    pub fn megabytes(n: u64) -> Self { Self(n * Self::MB) }
    pub fn gigabytes(n: u64) -> Self { Self(n * Self::GB) }

    pub fn as_bytes(&self) -> u64 { self.0 }

    pub fn human_readable(&self) -> String {
        if self.0 >= Self::TB {
            format!("{:.2} TB", self.0 as f64 / Self::TB as f64)
        } else if self.0 >= Self::GB {
            format!("{:.2} GB", self.0 as f64 / Self::GB as f64)
        } else if self.0 >= Self::MB {
            format!("{:.2} MB", self.0 as f64 / Self::MB as f64)
        } else if self.0 >= Self::KB {
            format!("{:.2} KB", self.0 as f64 / Self::KB as f64)
        } else {
            format!("{} B", self.0)
        }
    }
}

// ============================================================================
// Pagination
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    pub limit: u32,
    pub offset: Option<u64>,
    pub cursor: Option<String>,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            limit: 100,
            offset: None,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationInfo {
    pub total_count: u64,
    pub limit: u32,
    pub offset: u64,
    pub has_more: bool,
    pub next_cursor: Option<String>,
    pub prev_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub pagination: PaginationInfo,
}

impl<T> Page<T> {
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            pagination: PaginationInfo {
                total_count: 0,
                limit: 0,
                offset: 0,
                has_more: false,
                next_cursor: None,
                prev_cursor: None,
            },
        }
    }
}

// ============================================================================
// Metadata and Tags
// ============================================================================

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metadata {
    pub fields: HashMap<String, MetadataValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MetadataValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<MetadataValue>),
    Object(HashMap<String, MetadataValue>),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tag {
    pub key: String,
    pub value: Option<String>,
}

impl Tag {
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: None,
        }
    }

    pub fn with_value(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: Some(value.into()),
        }
    }
}

// ============================================================================
// Filters
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterExpression {
    pub conditions: Vec<FilterCondition>,
    pub operator: LogicalOperator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterCondition {
    Equals { field: String, value: MetadataValue },
    NotEquals { field: String, value: MetadataValue },
    GreaterThan { field: String, value: MetadataValue },
    LessThan { field: String, value: MetadataValue },
    Contains { field: String, value: String },
    StartsWith { field: String, value: String },
    In { field: String, values: Vec<MetadataValue> },
    IsNull { field: String },
    IsNotNull { field: String },
    And(Vec<FilterCondition>),
    Or(Vec<FilterCondition>),
    Not(Box<FilterCondition>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LogicalOperator {
    And,
    Or,
}

// ============================================================================
// Sort Options
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortOption {
    pub field: String,
    pub direction: SortDirection,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SortDirection {
    Ascending,
    Descending,
}
```

---

## 2. Dataset Types

```rust
// src/models/dataset.rs

use super::common::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Dataset
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    pub id: DatasetId,
    pub name: String,
    pub description: Option<String>,
    pub workspace_id: WorkspaceId,
    pub schema: Option<DatasetSchema>,
    pub current_version: VersionId,
    pub status: DatasetStatus,
    pub visibility: Visibility,
    pub tags: Vec<Tag>,
    pub metadata: Metadata,
    pub retention_policy: Option<PolicyId>,
    pub anonymization_policy: Option<PolicyId>,
    pub created_by: UserId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatasetStatus {
    Active,
    Archived,
    PendingDeletion,
    Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    Private,
    Workspace,
    Organization,
    Public,
}

impl Dataset {
    pub fn builder() -> DatasetBuilder {
        DatasetBuilder::default()
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.name.is_empty() {
            return Err(ValidationError::field("name", "Name cannot be empty"));
        }
        if self.name.len() > 256 {
            return Err(ValidationError::field("name", "Name exceeds 256 characters"));
        }
        // Additional validations...
        Ok(())
    }
}

#[derive(Default)]
pub struct DatasetBuilder {
    name: Option<String>,
    description: Option<String>,
    workspace_id: Option<WorkspaceId>,
    schema: Option<DatasetSchema>,
    tags: Vec<Tag>,
    metadata: Metadata,
    created_by: Option<UserId>,
}

impl DatasetBuilder {
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    pub fn workspace(mut self, id: WorkspaceId) -> Self {
        self.workspace_id = Some(id);
        self
    }

    pub fn schema(mut self, schema: DatasetSchema) -> Self {
        self.schema = Some(schema);
        self
    }

    pub fn tag(mut self, tag: Tag) -> Self {
        self.tags.push(tag);
        self
    }

    pub fn created_by(mut self, user: UserId) -> Self {
        self.created_by = Some(user);
        self
    }

    pub fn build(self) -> Result<Dataset, ValidationError> {
        let now = Utc::now();
        let id = DatasetId::new();
        let version_id = VersionId::new();

        let dataset = Dataset {
            id,
            name: self.name.ok_or(ValidationError::missing("name"))?,
            description: self.description,
            workspace_id: self.workspace_id.ok_or(ValidationError::missing("workspace_id"))?,
            schema: self.schema,
            current_version: version_id,
            status: DatasetStatus::Active,
            visibility: Visibility::Private,
            tags: self.tags,
            metadata: self.metadata,
            retention_policy: None,
            anonymization_policy: None,
            created_by: self.created_by.ok_or(ValidationError::missing("created_by"))?,
            created_at: now,
            updated_at: now,
        };

        dataset.validate()?;
        Ok(dataset)
    }
}

// ============================================================================
// Dataset Version
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetVersion {
    pub id: VersionId,
    pub dataset_id: DatasetId,
    pub version_number: u64,
    pub commit_hash: ContentHash,
    pub parent_versions: Vec<VersionId>,
    pub message: String,
    pub author: UserId,
    pub statistics: VersionStatistics,
    pub created_at: DateTime<Utc>,
    pub is_tagged: bool,
    pub signature: Option<VersionSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionStatistics {
    pub record_count: u64,
    pub total_size: ByteSize,
    pub added_records: u64,
    pub removed_records: u64,
    pub modified_records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionSignature {
    pub algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
    pub signer_id: UserId,
    pub signed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
}

// ============================================================================
// Dataset Schema
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSchema {
    pub version: String,
    pub fields: Vec<SchemaField>,
    pub primary_key: Option<Vec<String>>,
    pub indexes: Vec<SchemaIndex>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    pub name: String,
    pub field_type: FieldType,
    pub nullable: bool,
    pub default_value: Option<MetadataValue>,
    pub description: Option<String>,
    pub pii_classification: Option<PIIClassification>,
    pub constraints: Vec<FieldConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldType {
    String,
    Integer,
    Float,
    Boolean,
    Timestamp,
    Binary,
    Json,
    Array(Box<FieldType>),
    Map { key: Box<FieldType>, value: Box<FieldType> },
    Struct(Vec<SchemaField>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PIIClassification {
    None,
    Low,      // e.g., country
    Medium,   // e.g., city, age
    High,     // e.g., name, email
    Critical, // e.g., SSN, credit card
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldConstraint {
    MinLength(usize),
    MaxLength(usize),
    Pattern(String),
    MinValue(f64),
    MaxValue(f64),
    Enum(Vec<String>),
    Unique,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaIndex {
    pub name: String,
    pub fields: Vec<String>,
    pub unique: bool,
    pub index_type: IndexType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum IndexType {
    BTree,
    Hash,
    FullText,
}

// ============================================================================
// Dataset Metadata
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetMetadata {
    pub format: DataFormat,
    pub encoding: String,
    pub compression: Option<CompressionType>,
    pub partitioning: Option<PartitioningScheme>,
    pub lineage: LineageInfo,
    pub quality_metrics: QualityMetrics,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum DataFormat {
    Json,
    JsonLines,
    Parquet,
    Csv,
    Avro,
    Binary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CompressionType {
    None,
    Gzip,
    Zstd,
    Lz4,
    Snappy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitioningScheme {
    pub partition_keys: Vec<String>,
    pub partition_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageInfo {
    pub sources: Vec<LineageSource>,
    pub transformations: Vec<TransformationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageSource {
    pub source_type: SourceType,
    pub source_id: String,
    pub source_version: Option<String>,
    pub extracted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SourceType {
    Dataset,
    ExternalApi,
    FileUpload,
    Stream,
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationRecord {
    pub transformation_type: String,
    pub parameters: HashMap<String, MetadataValue>,
    pub applied_at: DateTime<Utc>,
    pub applied_by: UserId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    pub completeness: f64,       // 0.0 - 1.0
    pub validity: f64,           // 0.0 - 1.0
    pub uniqueness: f64,         // 0.0 - 1.0
    pub last_profiled: Option<DateTime<Utc>>,
    pub null_counts: HashMap<String, u64>,
    pub distinct_counts: HashMap<String, u64>,
}
```

---

## 3. Record Types

```rust
// src/models/record.rs

use super::common::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Data Record
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRecord {
    pub id: RecordId,
    pub dataset_id: DatasetId,
    pub version_id: VersionId,
    pub sequence_number: u64,
    pub data: RecordData,
    pub checksum: Checksum,
    pub size: ByteSize,
    pub created_at: DateTime<Utc>,
    pub metadata: RecordMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "content")]
pub enum RecordData {
    Structured(serde_json::Value),
    Text(String),
    Binary(#[serde(with = "serde_bytes")] Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordMetadata {
    pub source_id: Option<String>,
    pub ingestion_timestamp: DateTime<Utc>,
    pub labels: HashMap<String, String>,
    pub lineage_refs: Vec<LineageRef>,
    pub anonymization_status: AnonymizationStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum AnonymizationStatus {
    Original,
    Anonymized { policy_id: PolicyId },
    PartiallyAnonymized { policy_id: PolicyId },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageRef {
    pub source_dataset_id: DatasetId,
    pub source_record_id: RecordId,
    pub relationship: LineageRelationship,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LineageRelationship {
    DerivedFrom,
    CopiedFrom,
    TransformedFrom,
    MergedFrom,
    AnonymizedFrom,
}

// ============================================================================
// Record Batch
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordBatch {
    pub batch_id: Uuid,
    pub dataset_id: DatasetId,
    pub records: Vec<DataRecord>,
    pub batch_checksum: Checksum,
    pub total_size: ByteSize,
    pub created_at: DateTime<Utc>,
}

impl RecordBatch {
    pub fn new(dataset_id: DatasetId, records: Vec<DataRecord>) -> Self {
        let batch_id = Uuid::new_v4();
        let total_size = ByteSize(records.iter().map(|r| r.size.0).sum());

        // Compute batch checksum from record checksums
        let mut hasher = sha2::Sha256::new();
        for record in &records {
            if let Checksum::Sha256(bytes) = &record.checksum {
                hasher.update(bytes);
            }
        }
        let batch_checksum = Checksum::Sha256(hasher.finalize().into());

        Self {
            batch_id,
            dataset_id,
            records,
            batch_checksum,
            total_size,
            created_at: Utc::now(),
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.records.is_empty() {
            return Err(ValidationError::field("records", "Batch cannot be empty"));
        }

        for record in &self.records {
            if record.dataset_id != self.dataset_id {
                return Err(ValidationError::field(
                    "records",
                    "All records must belong to the same dataset"
                ));
            }
        }

        Ok(())
    }
}

// ============================================================================
// Record Schema (Runtime Schema Validation)
// ============================================================================

#[derive(Debug, Clone)]
pub struct RecordValidator {
    schema: DatasetSchema,
}

impl RecordValidator {
    pub fn new(schema: DatasetSchema) -> Self {
        Self { schema }
    }

    pub fn validate(&self, record: &DataRecord) -> Result<(), ValidationError> {
        match &record.data {
            RecordData::Structured(json) => self.validate_json(json),
            RecordData::Text(_) => Ok(()), // Text records don't have schema
            RecordData::Binary(_) => Ok(()), // Binary records don't have schema
        }
    }

    fn validate_json(&self, json: &serde_json::Value) -> Result<(), ValidationError> {
        let obj = json.as_object()
            .ok_or(ValidationError::field("data", "Expected JSON object"))?;

        for field in &self.schema.fields {
            let value = obj.get(&field.name);

            if value.is_none() || value == Some(&serde_json::Value::Null) {
                if !field.nullable && field.default_value.is_none() {
                    return Err(ValidationError::field(
                        &field.name,
                        format!("Required field '{}' is missing", field.name)
                    ));
                }
                continue;
            }

            self.validate_field_type(value.unwrap(), &field.field_type, &field.name)?;
            self.validate_constraints(value.unwrap(), &field.constraints, &field.name)?;
        }

        Ok(())
    }

    fn validate_field_type(
        &self,
        value: &serde_json::Value,
        field_type: &FieldType,
        field_name: &str
    ) -> Result<(), ValidationError> {
        match field_type {
            FieldType::String => {
                if !value.is_string() {
                    return Err(ValidationError::type_mismatch(field_name, "string"));
                }
            }
            FieldType::Integer => {
                if !value.is_i64() {
                    return Err(ValidationError::type_mismatch(field_name, "integer"));
                }
            }
            FieldType::Float => {
                if !value.is_f64() {
                    return Err(ValidationError::type_mismatch(field_name, "float"));
                }
            }
            FieldType::Boolean => {
                if !value.is_boolean() {
                    return Err(ValidationError::type_mismatch(field_name, "boolean"));
                }
            }
            FieldType::Array(inner) => {
                let arr = value.as_array()
                    .ok_or(ValidationError::type_mismatch(field_name, "array"))?;
                for (i, item) in arr.iter().enumerate() {
                    self.validate_field_type(
                        item,
                        inner,
                        &format!("{}[{}]", field_name, i)
                    )?;
                }
            }
            // Additional type validations...
            _ => {}
        }
        Ok(())
    }

    fn validate_constraints(
        &self,
        value: &serde_json::Value,
        constraints: &[FieldConstraint],
        field_name: &str
    ) -> Result<(), ValidationError> {
        for constraint in constraints {
            match constraint {
                FieldConstraint::MinLength(min) => {
                    if let Some(s) = value.as_str() {
                        if s.len() < *min {
                            return Err(ValidationError::constraint(
                                field_name,
                                format!("Length must be at least {}", min)
                            ));
                        }
                    }
                }
                FieldConstraint::MaxLength(max) => {
                    if let Some(s) = value.as_str() {
                        if s.len() > *max {
                            return Err(ValidationError::constraint(
                                field_name,
                                format!("Length must not exceed {}", max)
                            ));
                        }
                    }
                }
                FieldConstraint::Pattern(pattern) => {
                    if let Some(s) = value.as_str() {
                        let re = regex::Regex::new(pattern)
                            .map_err(|_| ValidationError::invalid_pattern(pattern))?;
                        if !re.is_match(s) {
                            return Err(ValidationError::constraint(
                                field_name,
                                format!("Value does not match pattern '{}'", pattern)
                            ));
                        }
                    }
                }
                // Additional constraint validations...
                _ => {}
            }
        }
        Ok(())
    }
}
```

---

## 4. Validation Error Types

```rust
// src/models/error.rs

use std::fmt;

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub kind: ValidationErrorKind,
    pub field: Option<String>,
    pub message: String,
    pub details: Vec<ValidationDetail>,
}

#[derive(Debug, Clone)]
pub enum ValidationErrorKind {
    MissingField,
    InvalidType,
    ConstraintViolation,
    InvalidPattern,
    InvalidValue,
    Custom,
}

#[derive(Debug, Clone)]
pub struct ValidationDetail {
    pub field: String,
    pub message: String,
    pub code: String,
}

impl ValidationError {
    pub fn missing(field: &str) -> Self {
        Self {
            kind: ValidationErrorKind::MissingField,
            field: Some(field.to_string()),
            message: format!("Required field '{}' is missing", field),
            details: vec![],
        }
    }

    pub fn field(field: &str, message: impl Into<String>) -> Self {
        Self {
            kind: ValidationErrorKind::InvalidValue,
            field: Some(field.to_string()),
            message: message.into(),
            details: vec![],
        }
    }

    pub fn type_mismatch(field: &str, expected: &str) -> Self {
        Self {
            kind: ValidationErrorKind::InvalidType,
            field: Some(field.to_string()),
            message: format!("Field '{}' expected type '{}'", field, expected),
            details: vec![],
        }
    }

    pub fn constraint(field: &str, message: impl Into<String>) -> Self {
        Self {
            kind: ValidationErrorKind::ConstraintViolation,
            field: Some(field.to_string()),
            message: message.into(),
            details: vec![],
        }
    }

    pub fn invalid_pattern(pattern: &str) -> Self {
        Self {
            kind: ValidationErrorKind::InvalidPattern,
            field: None,
            message: format!("Invalid regex pattern: '{}'", pattern),
            details: vec![],
        }
    }

    pub fn with_detail(mut self, detail: ValidationDetail) -> Self {
        self.details.push(detail);
        self
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref field) = self.field {
            write!(f, "[{}] {}", field, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

impl std::error::Error for ValidationError {}
```

---

## Summary

This document defines the foundational data models for LLM-Data-Vault:

| Component | Types | Purpose |
|-----------|-------|---------|
| **Common** | IDs, Checksum, ContentHash, Pagination, Metadata, Tags, Filters | Shared types across modules |
| **Dataset** | Dataset, DatasetVersion, DatasetSchema, DatasetMetadata | Dataset lifecycle management |
| **Record** | DataRecord, RecordBatch, RecordValidator | Individual data record handling |
| **Validation** | ValidationError, ValidationErrorKind | Type-safe error handling |

**Key Design Patterns:**
- Newtype pattern for type-safe IDs
- Builder pattern for complex object construction
- Validation methods on all major types
- Serde-compatible serialization
- Content-addressable storage support

---

*Next Document: [02-storage-layer.md](./02-storage-layer.md)*
