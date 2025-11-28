//! Data record types.

use crate::{ContentHash, DatasetId, RecordId, VersionId};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A data record within a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataRecord {
    /// Unique record identifier.
    pub id: RecordId,

    /// Dataset this record belongs to.
    pub dataset_id: DatasetId,

    /// Version this record belongs to.
    pub version_id: VersionId,

    /// The record data.
    pub data: RecordData,

    /// Content hash for integrity verification.
    pub content_hash: ContentHash,

    /// PII annotations (if detected).
    pub pii_annotations: Option<Vec<PIIAnnotation>>,

    /// Custom metadata.
    pub metadata: HashMap<String, serde_json::Value>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl DataRecord {
    /// Creates a new record builder.
    #[must_use]
    pub fn builder() -> RecordBuilder {
        RecordBuilder::default()
    }

    /// Returns the size of the record data in bytes.
    #[must_use]
    pub fn size_bytes(&self) -> usize {
        match &self.data {
            RecordData::Structured(v) => v.to_string().len(),
            RecordData::Text(s) => s.len(),
            RecordData::Binary(b) => b.len(),
        }
    }
}

/// Builder for creating records.
#[derive(Debug, Default)]
pub struct RecordBuilder {
    dataset_id: Option<DatasetId>,
    version_id: Option<VersionId>,
    data: Option<RecordData>,
    pii_annotations: Option<Vec<PIIAnnotation>>,
    metadata: HashMap<String, serde_json::Value>,
}

impl RecordBuilder {
    /// Sets the dataset ID.
    #[must_use]
    pub fn dataset_id(mut self, id: DatasetId) -> Self {
        self.dataset_id = Some(id);
        self
    }

    /// Sets the version ID.
    #[must_use]
    pub fn version_id(mut self, id: VersionId) -> Self {
        self.version_id = Some(id);
        self
    }

    /// Sets structured data.
    #[must_use]
    pub fn structured(mut self, data: serde_json::Value) -> Self {
        self.data = Some(RecordData::Structured(data));
        self
    }

    /// Sets text data.
    #[must_use]
    pub fn text(mut self, data: impl Into<String>) -> Self {
        self.data = Some(RecordData::Text(data.into()));
        self
    }

    /// Sets binary data.
    #[must_use]
    pub fn binary(mut self, data: impl Into<Bytes>) -> Self {
        self.data = Some(RecordData::Binary(data.into()));
        self
    }

    /// Sets PII annotations.
    #[must_use]
    pub fn pii_annotations(mut self, annotations: Vec<PIIAnnotation>) -> Self {
        self.pii_annotations = Some(annotations);
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Builds the record.
    ///
    /// # Panics
    /// Panics if required fields are not set.
    #[must_use]
    pub fn build(self) -> DataRecord {
        let data = self.data.expect("data is required");
        let content_hash = data.compute_hash();

        DataRecord {
            id: RecordId::new(),
            dataset_id: self.dataset_id.expect("dataset_id is required"),
            version_id: self.version_id.expect("version_id is required"),
            data,
            content_hash,
            pii_annotations: self.pii_annotations,
            metadata: self.metadata,
            created_at: Utc::now(),
        }
    }
}

/// The actual data content of a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "content")]
pub enum RecordData {
    /// Structured JSON data.
    Structured(serde_json::Value),
    /// Plain text data.
    Text(String),
    /// Binary data (base64 encoded in JSON).
    #[serde(with = "bytes_serde")]
    Binary(Bytes),
}

impl RecordData {
    /// Computes the content hash for this data.
    #[must_use]
    pub fn compute_hash(&self) -> ContentHash {
        let bytes = match self {
            Self::Structured(v) => v.to_string().into_bytes(),
            Self::Text(s) => s.as_bytes().to_vec(),
            Self::Binary(b) => b.to_vec(),
        };
        ContentHash::blake3(&bytes)
    }

    /// Returns true if this is structured data.
    #[must_use]
    pub const fn is_structured(&self) -> bool {
        matches!(self, Self::Structured(_))
    }

    /// Returns true if this is text data.
    #[must_use]
    pub const fn is_text(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// Returns true if this is binary data.
    #[must_use]
    pub const fn is_binary(&self) -> bool {
        matches!(self, Self::Binary(_))
    }

    /// Returns the data as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Structured(v) => v.to_string().into_bytes(),
            Self::Text(s) => s.as_bytes().to_vec(),
            Self::Binary(b) => b.to_vec(),
        }
    }
}

/// Serde support for Bytes.
mod bytes_serde {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        b64.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::Engine;
        let s = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)?;
        Ok(Bytes::from(bytes))
    }
}

/// Annotation marking detected PII within data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PIIAnnotation {
    /// Type of PII detected.
    pub pii_type: PIIType,

    /// Location in the data (byte range or JSON path).
    pub location: PIILocation,

    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,

    /// Risk level of this PII.
    pub risk_level: PIIRiskLevel,

    /// Original detected value (if preserved).
    pub detected_value: Option<String>,

    /// Whether the PII has been anonymized.
    pub is_anonymized: bool,

    /// Strategy used for anonymization (if any).
    pub anonymization_strategy: Option<String>,

    /// Method used for anonymization.
    pub anonymization_method: Option<String>,
}

/// Location of PII within data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PIILocation {
    /// Byte range within text/binary data.
    ByteRange {
        /// Start byte offset.
        start: usize,
        /// End byte offset (exclusive).
        end: usize,
    },
    /// JSON path for structured data.
    JsonPath {
        /// JSON path expression.
        path: String,
    },
    /// Field name.
    Field {
        /// Field name.
        name: String,
    },
}

impl PIILocation {
    /// Returns the start offset if this is a ByteRange.
    #[must_use]
    pub fn start(&self) -> Option<usize> {
        match self {
            Self::ByteRange { start, .. } => Some(*start),
            _ => None,
        }
    }

    /// Returns the end offset if this is a ByteRange.
    #[must_use]
    pub fn end(&self) -> Option<usize> {
        match self {
            Self::ByteRange { end, .. } => Some(*end),
            _ => None,
        }
    }

    /// Returns the path if this is a JsonPath.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::JsonPath { path } => Some(path),
            _ => None,
        }
    }

    /// Creates a new ByteRange location.
    #[must_use]
    pub fn byte_range(start: usize, end: usize) -> Self {
        Self::ByteRange { start, end }
    }

    /// Creates a new JsonPath location.
    #[must_use]
    pub fn json_path(path: impl Into<String>) -> Self {
        Self::JsonPath { path: path.into() }
    }
}

/// Types of Personally Identifiable Information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PIIType {
    /// Email address.
    Email,
    /// Phone number.
    PhoneNumber,
    /// Phone number (alias).
    Phone,
    /// Social Security Number.
    Ssn,
    /// Credit card number.
    CreditCard,
    /// Person's name.
    Name,
    /// Physical address.
    Address,
    /// Location/coordinates.
    Location,
    /// GPS coordinates.
    Coordinates,
    /// Date of birth.
    DateOfBirth,
    /// API key or secret.
    ApiKey,
    /// IP address.
    IpAddress,
    /// Medical record number.
    MedicalRecordNumber,
    /// Medical record (alias).
    MedicalRecord,
    /// Health information.
    HealthInfo,
    /// Driver's license number.
    DriversLicense,
    /// Passport number.
    PassportNumber,
    /// Bank account number.
    BankAccount,
    /// National ID number.
    NationalId,
    /// Biometric data.
    Biometric,
    /// Password.
    Password,
    /// Credentials.
    Credentials,
    /// Custom PII type.
    Custom,
}

impl PIIType {
    /// Returns the category of this PII type.
    #[must_use]
    pub const fn category(&self) -> PIICategory {
        match self {
            Self::Email | Self::PhoneNumber | Self::Phone | Self::Name | Self::Address => {
                PIICategory::ContactInformation
            }
            Self::Ssn | Self::DriversLicense | Self::PassportNumber | Self::NationalId => {
                PIICategory::GovernmentId
            }
            Self::CreditCard | Self::BankAccount => PIICategory::Financial,
            Self::DateOfBirth | Self::MedicalRecordNumber | Self::MedicalRecord | Self::HealthInfo | Self::Biometric => {
                PIICategory::Sensitive
            }
            Self::ApiKey | Self::IpAddress | Self::Password | Self::Credentials => PIICategory::Technical,
            Self::Location | Self::Coordinates => PIICategory::ContactInformation,
            Self::Custom => PIICategory::Other,
        }
    }

    /// Returns the risk level of this PII type.
    #[must_use]
    pub const fn risk_level(&self) -> PIIRiskLevel {
        match self {
            Self::Ssn | Self::CreditCard | Self::BankAccount | Self::MedicalRecordNumber | Self::MedicalRecord => {
                PIIRiskLevel::High
            }
            Self::DriversLicense | Self::PassportNumber | Self::NationalId | Self::ApiKey => {
                PIIRiskLevel::High
            }
            Self::Password | Self::Credentials | Self::Biometric | Self::HealthInfo => {
                PIIRiskLevel::High
            }
            Self::Name | Self::DateOfBirth | Self::Address | Self::PhoneNumber | Self::Phone => {
                PIIRiskLevel::Medium
            }
            Self::Location | Self::Coordinates => PIIRiskLevel::Medium,
            Self::Email | Self::IpAddress => PIIRiskLevel::Low,
            Self::Custom => PIIRiskLevel::Medium,
        }
    }
}

/// Category of PII.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PIICategory {
    /// Contact information (email, phone, address).
    ContactInformation,
    /// Government-issued IDs.
    GovernmentId,
    /// Financial information.
    Financial,
    /// Sensitive personal information.
    Sensitive,
    /// Technical identifiers.
    Technical,
    /// Other/custom categories.
    Other,
}

/// Risk level of PII.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PIIRiskLevel {
    /// Low risk.
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
    /// Critical risk (most sensitive).
    Critical,
}

/// Request to add multiple records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddRecordsRequest {
    /// Records to add.
    pub records: Vec<serde_json::Value>,
    /// Whether to validate against schema.
    pub validate_schema: bool,
    /// Idempotency key for safe retries.
    pub idempotency_key: Option<String>,
}

/// Response from adding records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddRecordsResponse {
    /// Number of records successfully added.
    pub records_added: u64,
    /// Number of records rejected.
    pub records_rejected: u64,
    /// Validation errors for rejected records.
    pub errors: Vec<RecordError>,
    /// Idempotency key used.
    pub idempotency_key: Option<String>,
}

/// Error for a specific record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordError {
    /// Index of the record in the request.
    pub index: usize,
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_builder() {
        let record = DataRecord::builder()
            .dataset_id(DatasetId::new())
            .version_id(VersionId::new())
            .text("Hello, World!")
            .metadata("source", serde_json::json!("test"))
            .build();

        assert!(record.data.is_text());
        assert!(!record.content_hash.hash.is_empty());
    }

    #[test]
    fn test_pii_type_risk_level() {
        assert_eq!(PIIType::Ssn.risk_level(), PIIRiskLevel::High);
        assert_eq!(PIIType::Email.risk_level(), PIIRiskLevel::Low);
        assert_eq!(PIIType::Name.risk_level(), PIIRiskLevel::Medium);
    }

    #[test]
    fn test_record_data_hash() {
        let data1 = RecordData::Text("test".to_string());
        let data2 = RecordData::Text("test".to_string());
        let data3 = RecordData::Text("different".to_string());

        assert_eq!(data1.compute_hash().hash, data2.compute_hash().hash);
        assert_ne!(data1.compute_hash().hash, data3.compute_hash().hash);
    }
}
