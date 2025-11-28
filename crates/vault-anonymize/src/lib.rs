//! PII detection and anonymization for LLM Data Vault.
//!
//! This crate provides comprehensive PII (Personally Identifiable Information)
//! detection and anonymization capabilities with 99.5%+ accuracy target.

pub mod error;
pub mod detector;
pub mod anonymizer;
pub mod strategy;
pub mod patterns;
pub mod config;
pub mod context;

pub use error::{AnonymizeError, AnonymizeResult};
pub use detector::{PiiDetector, Detection, DetectorConfig, DetectionMethod};
pub use anonymizer::{Anonymizer, AnonymizerConfig, AnonymizedOutput};
pub use strategy::{AnonymizationStrategy, StrategyConfig, StrategyExecutor};
pub use patterns::{PatternMatcher, Pattern, PatternSet, PatternMatch};
pub use context::{AnonymizationContext, ContextualDetector};

use vault_core::record::PIIType;

/// Re-export common types.
pub use vault_core::record::{PIIAnnotation, PIILocation, PIIRiskLevel};

/// PII category groupings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PIICategory {
    /// Direct identifiers (name, SSN, etc.).
    DirectIdentifier,
    /// Contact information (email, phone, address).
    ContactInfo,
    /// Financial data (credit card, bank account).
    Financial,
    /// Health and medical data.
    Health,
    /// Authentication credentials.
    Credentials,
    /// Biometric data.
    Biometric,
    /// Location data.
    Location,
    /// Online identifiers (IP, device ID).
    OnlineIdentifier,
    /// Government IDs.
    GovernmentId,
    /// Other sensitive data.
    Other,
}

impl PIICategory {
    /// Returns the category for a PII type.
    #[must_use]
    pub fn from_pii_type(pii_type: &PIIType) -> Self {
        match pii_type {
            PIIType::Email | PIIType::Phone | PIIType::PhoneNumber | PIIType::Address => Self::ContactInfo,
            PIIType::Name => Self::DirectIdentifier,
            PIIType::Ssn | PIIType::DriversLicense | PIIType::PassportNumber | PIIType::NationalId => {
                Self::GovernmentId
            }
            PIIType::CreditCard | PIIType::BankAccount => Self::Financial,
            PIIType::DateOfBirth => Self::DirectIdentifier,
            PIIType::IpAddress => Self::OnlineIdentifier,
            PIIType::Location | PIIType::Coordinates => Self::Location,
            PIIType::Biometric => Self::Biometric,
            PIIType::MedicalRecordNumber | PIIType::MedicalRecord | PIIType::HealthInfo => Self::Health,
            PIIType::Password | PIIType::ApiKey | PIIType::Credentials => Self::Credentials,
            PIIType::Custom => Self::Other,
        }
    }

    /// Returns the default risk level for this category.
    #[must_use]
    pub fn default_risk_level(&self) -> PIIRiskLevel {
        match self {
            Self::DirectIdentifier | Self::GovernmentId | Self::Biometric => PIIRiskLevel::Critical,
            Self::Financial | Self::Health | Self::Credentials => PIIRiskLevel::High,
            Self::ContactInfo | Self::Location => PIIRiskLevel::Medium,
            Self::OnlineIdentifier | Self::Other => PIIRiskLevel::Low,
        }
    }
}

/// Compliance framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ComplianceFramework {
    /// GDPR (EU General Data Protection Regulation).
    Gdpr,
    /// CCPA (California Consumer Privacy Act).
    Ccpa,
    /// HIPAA (Health Insurance Portability and Accountability Act).
    Hipaa,
    /// PCI-DSS (Payment Card Industry Data Security Standard).
    PciDss,
    /// SOC 2.
    Soc2,
    /// Custom framework.
    Custom,
}

impl ComplianceFramework {
    /// Returns the PII types that must be protected under this framework.
    #[must_use]
    pub fn required_pii_types(&self) -> Vec<PIIType> {
        match self {
            Self::Gdpr => vec![
                PIIType::Name,
                PIIType::Email,
                PIIType::PhoneNumber,
                PIIType::Address,
                PIIType::IpAddress,
                PIIType::Location,
                PIIType::DateOfBirth,
                PIIType::NationalId,
                PIIType::Biometric,
                PIIType::HealthInfo,
            ],
            Self::Ccpa => vec![
                PIIType::Name,
                PIIType::Email,
                PIIType::PhoneNumber,
                PIIType::Address,
                PIIType::Ssn,
                PIIType::DriversLicense,
                PIIType::IpAddress,
                PIIType::Location,
                PIIType::Biometric,
            ],
            Self::Hipaa => vec![
                PIIType::Name,
                PIIType::Address,
                PIIType::DateOfBirth,
                PIIType::PhoneNumber,
                PIIType::Email,
                PIIType::Ssn,
                PIIType::MedicalRecordNumber,
                PIIType::HealthInfo,
                PIIType::Biometric,
            ],
            Self::PciDss => vec![
                PIIType::CreditCard,
                PIIType::Name,
                PIIType::Address,
            ],
            Self::Soc2 => vec![
                PIIType::Name,
                PIIType::Email,
                PIIType::Password,
                PIIType::ApiKey,
                PIIType::Credentials,
            ],
            Self::Custom => vec![],
        }
    }

    /// Returns the minimum risk level that requires protection.
    #[must_use]
    pub fn minimum_protection_level(&self) -> PIIRiskLevel {
        match self {
            Self::Hipaa | Self::PciDss => PIIRiskLevel::Low,
            Self::Gdpr | Self::Ccpa => PIIRiskLevel::Medium,
            Self::Soc2 | Self::Custom => PIIRiskLevel::High,
        }
    }
}
