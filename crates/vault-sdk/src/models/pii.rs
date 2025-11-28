//! PII detection and anonymization models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// PII detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiDetectionResult {
    /// Unique result ID.
    pub id: Uuid,

    /// Source record ID (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<Uuid>,

    /// Detected PII entities.
    pub entities: Vec<PiiEntity>,

    /// Total entities found.
    pub entity_count: usize,

    /// Processing time in milliseconds.
    pub processing_time_ms: u64,

    /// Detection timestamp.
    pub detected_at: DateTime<Utc>,
}

/// A detected PII entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiEntity {
    /// PII type.
    pub pii_type: PiiType,

    /// Start position in text.
    pub start: usize,

    /// End position in text.
    pub end: usize,

    /// The detected text (may be redacted).
    pub text: String,

    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,

    /// Field path where PII was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,

    /// Context around the detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

/// Types of PII that can be detected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PiiType {
    /// Email address.
    Email,
    /// Phone number.
    Phone,
    /// Social Security Number.
    Ssn,
    /// Credit card number.
    CreditCard,
    /// Person name.
    PersonName,
    /// Physical address.
    Address,
    /// Date of birth.
    DateOfBirth,
    /// IP address.
    IpAddress,
    /// Passport number.
    Passport,
    /// Driver's license number.
    DriversLicense,
    /// Bank account number.
    BankAccount,
    /// Medical record number.
    MedicalRecordNumber,
    /// National ID (various countries).
    NationalId,
    /// Tax ID number.
    TaxId,
    /// Vehicle identification number.
    Vin,
    /// License plate.
    LicensePlate,
    /// Username or account ID.
    Username,
    /// Password or credential.
    Password,
    /// API key or secret.
    ApiKey,
    /// Custom PII type.
    Custom,
}

impl std::fmt::Display for PiiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Email => write!(f, "EMAIL"),
            Self::Phone => write!(f, "PHONE"),
            Self::Ssn => write!(f, "SSN"),
            Self::CreditCard => write!(f, "CREDIT_CARD"),
            Self::PersonName => write!(f, "PERSON_NAME"),
            Self::Address => write!(f, "ADDRESS"),
            Self::DateOfBirth => write!(f, "DATE_OF_BIRTH"),
            Self::IpAddress => write!(f, "IP_ADDRESS"),
            Self::Passport => write!(f, "PASSPORT"),
            Self::DriversLicense => write!(f, "DRIVERS_LICENSE"),
            Self::BankAccount => write!(f, "BANK_ACCOUNT"),
            Self::MedicalRecordNumber => write!(f, "MEDICAL_RECORD_NUMBER"),
            Self::NationalId => write!(f, "NATIONAL_ID"),
            Self::TaxId => write!(f, "TAX_ID"),
            Self::Vin => write!(f, "VIN"),
            Self::LicensePlate => write!(f, "LICENSE_PLATE"),
            Self::Username => write!(f, "USERNAME"),
            Self::Password => write!(f, "PASSWORD"),
            Self::ApiKey => write!(f, "API_KEY"),
            Self::Custom => write!(f, "CUSTOM"),
        }
    }
}

impl std::str::FromStr for PiiType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "EMAIL" => Ok(Self::Email),
            "PHONE" => Ok(Self::Phone),
            "SSN" => Ok(Self::Ssn),
            "CREDIT_CARD" => Ok(Self::CreditCard),
            "PERSON_NAME" => Ok(Self::PersonName),
            "ADDRESS" => Ok(Self::Address),
            "DATE_OF_BIRTH" => Ok(Self::DateOfBirth),
            "IP_ADDRESS" => Ok(Self::IpAddress),
            "PASSPORT" => Ok(Self::Passport),
            "DRIVERS_LICENSE" => Ok(Self::DriversLicense),
            "BANK_ACCOUNT" => Ok(Self::BankAccount),
            "MEDICAL_RECORD_NUMBER" => Ok(Self::MedicalRecordNumber),
            "NATIONAL_ID" => Ok(Self::NationalId),
            "TAX_ID" => Ok(Self::TaxId),
            "VIN" => Ok(Self::Vin),
            "LICENSE_PLATE" => Ok(Self::LicensePlate),
            "USERNAME" => Ok(Self::Username),
            "PASSWORD" => Ok(Self::Password),
            "API_KEY" => Ok(Self::ApiKey),
            "CUSTOM" => Ok(Self::Custom),
            _ => Err(format!("Unknown PII type: {s}")),
        }
    }
}

/// Request to detect PII in text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiDetectionRequest {
    /// Text to analyze.
    pub text: String,

    /// PII types to detect (empty = all types).
    #[serde(default)]
    pub pii_types: Vec<PiiType>,

    /// Minimum confidence threshold (0.0 - 1.0).
    #[serde(default = "default_confidence")]
    pub min_confidence: f32,

    /// Include context around detections.
    #[serde(default)]
    pub include_context: bool,

    /// Language hint for better detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

fn default_confidence() -> f32 {
    0.8
}

impl PiiDetectionRequest {
    /// Creates a new detection request.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            pii_types: Vec::new(),
            min_confidence: 0.8,
            include_context: false,
            language: None,
        }
    }

    /// Limits detection to specific PII types.
    #[must_use]
    pub fn with_types(mut self, types: Vec<PiiType>) -> Self {
        self.pii_types = types;
        self
    }

    /// Sets minimum confidence threshold.
    #[must_use]
    pub fn with_min_confidence(mut self, confidence: f32) -> Self {
        self.min_confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Includes context around detections.
    #[must_use]
    pub fn with_context(mut self) -> Self {
        self.include_context = true;
        self
    }

    /// Sets language hint.
    #[must_use]
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.language = Some(language.into());
        self
    }
}

/// Request to anonymize text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationRequest {
    /// Text to anonymize.
    pub text: String,

    /// Anonymization strategy.
    #[serde(default)]
    pub strategy: AnonymizationStrategy,

    /// PII types to anonymize (empty = all detected types).
    #[serde(default)]
    pub pii_types: Vec<PiiType>,

    /// Per-type strategy overrides.
    #[serde(default)]
    pub type_strategies: std::collections::HashMap<PiiType, AnonymizationStrategy>,

    /// Minimum confidence threshold.
    #[serde(default = "default_confidence")]
    pub min_confidence: f32,
}

impl AnonymizationRequest {
    /// Creates a new anonymization request.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            strategy: AnonymizationStrategy::default(),
            pii_types: Vec::new(),
            type_strategies: std::collections::HashMap::new(),
            min_confidence: 0.8,
        }
    }

    /// Sets the default strategy.
    #[must_use]
    pub fn with_strategy(mut self, strategy: AnonymizationStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Limits anonymization to specific types.
    #[must_use]
    pub fn with_types(mut self, types: Vec<PiiType>) -> Self {
        self.pii_types = types;
        self
    }

    /// Sets strategy for a specific PII type.
    #[must_use]
    pub fn with_type_strategy(mut self, pii_type: PiiType, strategy: AnonymizationStrategy) -> Self {
        self.type_strategies.insert(pii_type, strategy);
        self
    }

    /// Sets minimum confidence threshold.
    #[must_use]
    pub fn with_min_confidence(mut self, confidence: f32) -> Self {
        self.min_confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

/// Anonymization strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnonymizationStrategy {
    /// Replace with a placeholder like [EMAIL].
    Redact,
    /// Replace with asterisks (j***@***.com).
    Mask,
    /// Replace with realistic fake data.
    Replace,
    /// Replace with consistent hash-based pseudonym.
    Pseudonymize,
    /// Generalize (e.g., "New York" -> "US City").
    Generalize,
    /// Encrypt the value.
    Encrypt,
    /// Remove entirely.
    Remove,
}

impl Default for AnonymizationStrategy {
    fn default() -> Self {
        Self::Redact
    }
}

impl std::fmt::Display for AnonymizationStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redact => write!(f, "redact"),
            Self::Mask => write!(f, "mask"),
            Self::Replace => write!(f, "replace"),
            Self::Pseudonymize => write!(f, "pseudonymize"),
            Self::Generalize => write!(f, "generalize"),
            Self::Encrypt => write!(f, "encrypt"),
            Self::Remove => write!(f, "remove"),
        }
    }
}

impl std::str::FromStr for AnonymizationStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "redact" => Ok(Self::Redact),
            "mask" => Ok(Self::Mask),
            "replace" => Ok(Self::Replace),
            "pseudonymize" => Ok(Self::Pseudonymize),
            "generalize" => Ok(Self::Generalize),
            "encrypt" => Ok(Self::Encrypt),
            "remove" => Ok(Self::Remove),
            _ => Err(format!("Unknown anonymization strategy: {s}")),
        }
    }
}

/// Anonymization result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationResult {
    /// Anonymized text.
    pub anonymized_text: String,

    /// Original text (if requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_text: Option<String>,

    /// Applied transformations.
    pub transformations: Vec<Transformation>,

    /// Number of entities anonymized.
    pub entity_count: usize,

    /// Processing time in milliseconds.
    pub processing_time_ms: u64,
}

/// A transformation applied during anonymization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transformation {
    /// PII type that was transformed.
    pub pii_type: PiiType,

    /// Strategy used.
    pub strategy: AnonymizationStrategy,

    /// Original start position.
    pub original_start: usize,

    /// Original end position.
    pub original_end: usize,

    /// Replacement value (may be redacted).
    pub replacement: String,
}

/// PII scanning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiScanConfig {
    /// Enable automatic scanning.
    pub enabled: bool,

    /// PII types to detect.
    pub pii_types: Vec<PiiType>,

    /// Minimum confidence threshold.
    pub min_confidence: f32,

    /// Action on PII detection.
    pub on_detection: PiiAction,

    /// Auto-anonymization strategy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymization_strategy: Option<AnonymizationStrategy>,
}

impl Default for PiiScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pii_types: Vec::new(), // Empty = all types
            min_confidence: 0.8,
            on_detection: PiiAction::Flag,
            anonymization_strategy: None,
        }
    }
}

/// Action to take when PII is detected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PiiAction {
    /// Allow the record but flag it.
    Flag,
    /// Quarantine the record for review.
    Quarantine,
    /// Reject the record.
    Reject,
    /// Auto-anonymize the PII.
    Anonymize,
}
