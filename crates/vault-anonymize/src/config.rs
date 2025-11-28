//! Anonymization configuration.

use crate::{AnonymizationStrategy, ComplianceFramework, PIIRiskLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vault_core::record::PIIType;

/// Anonymization policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationPolicy {
    /// Policy name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// Compliance frameworks.
    pub compliance: Vec<ComplianceFramework>,
    /// Default strategy.
    pub default_strategy: AnonymizationStrategy,
    /// Type-specific rules.
    pub rules: Vec<AnonymizationRule>,
    /// Field path rules.
    pub field_rules: Vec<FieldRule>,
    /// Enabled.
    pub enabled: bool,
    /// Priority (higher = applied first).
    pub priority: i32,
}

impl AnonymizationPolicy {
    /// Creates a new policy.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            compliance: Vec::new(),
            default_strategy: AnonymizationStrategy::Mask,
            rules: Vec::new(),
            field_rules: Vec::new(),
            enabled: true,
            priority: 0,
        }
    }

    /// Creates a GDPR policy.
    pub fn gdpr() -> Self {
        let mut policy = Self::new("GDPR");
        policy.description = Some("EU General Data Protection Regulation compliance".to_string());
        policy.compliance = vec![ComplianceFramework::Gdpr];
        policy.default_strategy = AnonymizationStrategy::Mask;

        policy.rules = vec![
            AnonymizationRule::new(PIIType::Name, AnonymizationStrategy::Substitute),
            AnonymizationRule::new(PIIType::Email, AnonymizationStrategy::Mask),
            AnonymizationRule::new(PIIType::Phone, AnonymizationStrategy::Mask),
            AnonymizationRule::new(PIIType::Address, AnonymizationStrategy::Generalize),
            AnonymizationRule::new(PIIType::IpAddress, AnonymizationStrategy::Mask),
            AnonymizationRule::new(PIIType::Location, AnonymizationStrategy::Generalize),
            AnonymizationRule::new(PIIType::Biometric, AnonymizationStrategy::Redact),
        ];

        policy
    }

    /// Creates a HIPAA policy.
    pub fn hipaa() -> Self {
        let mut policy = Self::new("HIPAA");
        policy.description = Some("Health Insurance Portability and Accountability Act compliance".to_string());
        policy.compliance = vec![ComplianceFramework::Hipaa];
        policy.default_strategy = AnonymizationStrategy::Redact;

        policy.rules = vec![
            AnonymizationRule::new(PIIType::Name, AnonymizationStrategy::Substitute)
                .with_preserve_partial(true),
            AnonymizationRule::new(PIIType::DateOfBirth, AnonymizationStrategy::Generalize)
                .with_metadata("generalize_to", "year"),
            AnonymizationRule::new(PIIType::Ssn, AnonymizationStrategy::Redact),
            AnonymizationRule::new(PIIType::MedicalRecord, AnonymizationStrategy::Tokenize)
                .with_reversible(true),
            AnonymizationRule::new(PIIType::HealthInfo, AnonymizationStrategy::Redact),
            AnonymizationRule::new(PIIType::Address, AnonymizationStrategy::Generalize)
                .with_metadata("generalize_to", "state"),
        ];

        policy
    }

    /// Creates a PCI-DSS policy.
    pub fn pci_dss() -> Self {
        let mut policy = Self::new("PCI-DSS");
        policy.description = Some("Payment Card Industry Data Security Standard compliance".to_string());
        policy.compliance = vec![ComplianceFramework::PciDss];
        policy.default_strategy = AnonymizationStrategy::Mask;

        policy.rules = vec![
            AnonymizationRule::new(PIIType::CreditCard, AnonymizationStrategy::Mask)
                .with_preserve_partial(true)
                .with_metadata("visible_digits", "4"),
            AnonymizationRule::new(PIIType::BankAccount, AnonymizationStrategy::Redact),
            AnonymizationRule::new(PIIType::Name, AnonymizationStrategy::Mask),
        ];

        policy
    }

    /// Adds a rule.
    #[must_use]
    pub fn with_rule(mut self, rule: AnonymizationRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Adds a field rule.
    #[must_use]
    pub fn with_field_rule(mut self, rule: FieldRule) -> Self {
        self.field_rules.push(rule);
        self
    }

    /// Gets the strategy for a PII type.
    #[must_use]
    pub fn strategy_for(&self, pii_type: &PIIType) -> Option<AnonymizationStrategy> {
        self.rules
            .iter()
            .find(|r| r.pii_type == *pii_type)
            .map(|r| r.strategy)
    }

    /// Gets the strategy for a field path.
    #[must_use]
    pub fn strategy_for_field(&self, path: &str) -> Option<AnonymizationStrategy> {
        for rule in &self.field_rules {
            if rule.matches(path) {
                return Some(rule.strategy);
            }
        }
        None
    }
}

/// Anonymization rule for a specific PII type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationRule {
    /// PII type.
    pub pii_type: PIIType,
    /// Strategy to apply.
    pub strategy: AnonymizationStrategy,
    /// Minimum confidence to trigger.
    pub min_confidence: f64,
    /// Minimum risk level.
    pub min_risk_level: PIIRiskLevel,
    /// Preserve partial data (e.g., last 4 digits).
    pub preserve_partial: bool,
    /// Allow reversal (for tokenization).
    pub reversible: bool,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

impl AnonymizationRule {
    /// Creates a new rule.
    pub fn new(pii_type: PIIType, strategy: AnonymizationStrategy) -> Self {
        Self {
            pii_type,
            strategy,
            min_confidence: 0.5,
            min_risk_level: PIIRiskLevel::Low,
            preserve_partial: false,
            reversible: false,
            metadata: HashMap::new(),
        }
    }

    /// Sets minimum confidence.
    #[must_use]
    pub fn with_min_confidence(mut self, confidence: f64) -> Self {
        self.min_confidence = confidence;
        self
    }

    /// Sets minimum risk level.
    #[must_use]
    pub fn with_min_risk_level(mut self, level: PIIRiskLevel) -> Self {
        self.min_risk_level = level;
        self
    }

    /// Sets preserve partial.
    #[must_use]
    pub fn with_preserve_partial(mut self, preserve: bool) -> Self {
        self.preserve_partial = preserve;
        self
    }

    /// Sets reversible.
    #[must_use]
    pub fn with_reversible(mut self, reversible: bool) -> Self {
        self.reversible = reversible;
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Field-based anonymization rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRule {
    /// Field path pattern (supports wildcards).
    pub path_pattern: String,
    /// Strategy to apply.
    pub strategy: AnonymizationStrategy,
    /// Is regex pattern.
    pub is_regex: bool,
    /// PII type hint.
    pub pii_type_hint: Option<PIIType>,
}

impl FieldRule {
    /// Creates a new field rule.
    pub fn new(path_pattern: impl Into<String>, strategy: AnonymizationStrategy) -> Self {
        Self {
            path_pattern: path_pattern.into(),
            strategy,
            is_regex: false,
            pii_type_hint: None,
        }
    }

    /// Creates a regex-based rule.
    pub fn regex(pattern: impl Into<String>, strategy: AnonymizationStrategy) -> Self {
        Self {
            path_pattern: pattern.into(),
            strategy,
            is_regex: true,
            pii_type_hint: None,
        }
    }

    /// Sets PII type hint.
    #[must_use]
    pub fn with_pii_type_hint(mut self, pii_type: PIIType) -> Self {
        self.pii_type_hint = Some(pii_type);
        self
    }

    /// Checks if the rule matches a path.
    pub fn matches(&self, path: &str) -> bool {
        if self.is_regex {
            regex::Regex::new(&self.path_pattern)
                .map(|r| r.is_match(path))
                .unwrap_or(false)
        } else {
            // Simple wildcard matching
            let pattern = self.path_pattern.replace("*", ".*");
            regex::Regex::new(&format!("^{}$", pattern))
                .map(|r| r.is_match(path))
                .unwrap_or(false)
        }
    }
}

/// Policy set for managing multiple policies.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    policies: Vec<AnonymizationPolicy>,
}

impl PolicySet {
    /// Creates a new policy set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Creates with common compliance policies.
    #[must_use]
    pub fn with_compliance() -> Self {
        let mut set = Self::new();
        set.add(AnonymizationPolicy::gdpr());
        set.add(AnonymizationPolicy::hipaa());
        set.add(AnonymizationPolicy::pci_dss());
        set
    }

    /// Adds a policy.
    pub fn add(&mut self, policy: AnonymizationPolicy) {
        self.policies.push(policy);
        self.policies.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Gets the effective strategy for a PII type.
    #[must_use]
    pub fn effective_strategy(&self, pii_type: &PIIType) -> Option<AnonymizationStrategy> {
        for policy in &self.policies {
            if policy.enabled {
                if let Some(strategy) = policy.strategy_for(pii_type) {
                    return Some(strategy);
                }
            }
        }
        None
    }

    /// Gets the effective strategy for a field.
    #[must_use]
    pub fn effective_field_strategy(&self, path: &str) -> Option<AnonymizationStrategy> {
        for policy in &self.policies {
            if policy.enabled {
                if let Some(strategy) = policy.strategy_for_field(path) {
                    return Some(strategy);
                }
            }
        }
        None
    }

    /// Returns all enabled policies.
    #[must_use]
    pub fn enabled_policies(&self) -> Vec<&AnonymizationPolicy> {
        self.policies.iter().filter(|p| p.enabled).collect()
    }

    /// Returns policies for a compliance framework.
    #[must_use]
    pub fn policies_for_compliance(&self, framework: ComplianceFramework) -> Vec<&AnonymizationPolicy> {
        self.policies
            .iter()
            .filter(|p| p.compliance.contains(&framework))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gdpr_policy() {
        let policy = AnonymizationPolicy::gdpr();

        assert_eq!(policy.name, "GDPR");
        assert!(policy.compliance.contains(&ComplianceFramework::Gdpr));

        let email_strategy = policy.strategy_for(&PIIType::Email);
        assert_eq!(email_strategy, Some(AnonymizationStrategy::Mask));
    }

    #[test]
    fn test_hipaa_policy() {
        let policy = AnonymizationPolicy::hipaa();

        let ssn_strategy = policy.strategy_for(&PIIType::Ssn);
        assert_eq!(ssn_strategy, Some(AnonymizationStrategy::Redact));

        let dob_strategy = policy.strategy_for(&PIIType::DateOfBirth);
        assert_eq!(dob_strategy, Some(AnonymizationStrategy::Generalize));
    }

    #[test]
    fn test_field_rule() {
        let rule = FieldRule::new("user.*.email", AnonymizationStrategy::Mask);

        assert!(rule.matches("user.profile.email"));
        assert!(rule.matches("user.settings.email"));
        assert!(!rule.matches("admin.email"));
    }

    #[test]
    fn test_policy_set() {
        let set = PolicySet::with_compliance();

        // Should find GDPR strategy for email
        let email_strategy = set.effective_strategy(&PIIType::Email);
        assert!(email_strategy.is_some());

        // Should find PCI-DSS strategy for credit card
        let cc_strategy = set.effective_strategy(&PIIType::CreditCard);
        assert!(cc_strategy.is_some());
    }

    #[test]
    fn test_rule_with_metadata() {
        let rule = AnonymizationRule::new(PIIType::CreditCard, AnonymizationStrategy::Mask)
            .with_preserve_partial(true)
            .with_metadata("visible_digits", "4");

        assert!(rule.preserve_partial);
        assert_eq!(rule.metadata.get("visible_digits"), Some(&"4".to_string()));
    }
}
