//! PII pattern matching.

use crate::{AnonymizeError, AnonymizeResult, PIIRiskLevel};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vault_core::record::PIIType;

/// Built-in patterns for common PII types.
pub static BUILTIN_PATTERNS: Lazy<PatternSet> = Lazy::new(PatternSet::builtin);

/// A PII detection pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Pattern name.
    pub name: String,
    /// PII type this pattern detects.
    pub pii_type: PIIType,
    /// Regular expression pattern.
    pub regex: String,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Risk level.
    pub risk_level: PIIRiskLevel,
    /// Description.
    pub description: Option<String>,
    /// Validation function name (if any).
    pub validator: Option<String>,
    /// Priority (higher = checked first).
    pub priority: i32,
}

impl Pattern {
    /// Creates a new pattern.
    pub fn new(
        name: impl Into<String>,
        pii_type: PIIType,
        regex: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            pii_type,
            regex: regex.into(),
            confidence: 0.8,
            risk_level: PIIRiskLevel::Medium,
            description: None,
            validator: None,
            priority: 0,
        }
    }

    /// Sets confidence.
    #[must_use]
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Sets risk level.
    #[must_use]
    pub fn with_risk_level(mut self, level: PIIRiskLevel) -> Self {
        self.risk_level = level;
        self
    }

    /// Sets validator.
    #[must_use]
    pub fn with_validator(mut self, validator: impl Into<String>) -> Self {
        self.validator = Some(validator.into());
        self
    }

    /// Sets priority.
    #[must_use]
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }
}

/// A compiled pattern ready for matching.
pub struct CompiledPattern {
    /// Original pattern.
    pub pattern: Pattern,
    /// Compiled regex.
    regex: Regex,
}

impl CompiledPattern {
    /// Compiles a pattern.
    pub fn compile(pattern: Pattern) -> AnonymizeResult<Self> {
        let regex = Regex::new(&pattern.regex)?;
        Ok(Self { pattern, regex })
    }

    /// Finds all matches in text.
    pub fn find_matches(&self, text: &str) -> Vec<PatternMatch> {
        self.regex
            .find_iter(text)
            .map(|m| PatternMatch {
                pattern_name: self.pattern.name.clone(),
                pii_type: self.pattern.pii_type.clone(),
                start: m.start(),
                end: m.end(),
                matched_text: m.as_str().to_string(),
                confidence: self.pattern.confidence,
                risk_level: self.pattern.risk_level,
            })
            .collect()
    }

    /// Checks if the pattern matches anywhere in text.
    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

/// A pattern match result.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Pattern name that matched.
    pub pattern_name: String,
    /// PII type detected.
    pub pii_type: PIIType,
    /// Start offset in text.
    pub start: usize,
    /// End offset in text.
    pub end: usize,
    /// Matched text.
    pub matched_text: String,
    /// Confidence score.
    pub confidence: f64,
    /// Risk level.
    pub risk_level: PIIRiskLevel,
}

/// A set of patterns for PII detection.
pub struct PatternSet {
    patterns: Vec<CompiledPattern>,
    by_type: HashMap<PIIType, Vec<usize>>,
}

impl PatternSet {
    /// Creates an empty pattern set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            by_type: HashMap::new(),
        }
    }

    /// Creates built-in patterns.
    #[must_use]
    pub fn builtin() -> Self {
        let mut set = Self::new();

        // Email patterns
        set.add(Pattern::new(
            "email",
            PIIType::Email,
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        ).with_confidence(0.95).with_risk_level(PIIRiskLevel::Medium));

        // Phone patterns (various formats)
        set.add(Pattern::new(
            "phone_us",
            PIIType::Phone,
            r"(?:\+1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
        ).with_confidence(0.85).with_risk_level(PIIRiskLevel::Medium));

        set.add(Pattern::new(
            "phone_intl",
            PIIType::Phone,
            r"\+[1-9]\d{1,14}",
        ).with_confidence(0.80).with_risk_level(PIIRiskLevel::Medium));

        // SSN (US Social Security Number)
        set.add(Pattern::new(
            "ssn",
            PIIType::Ssn,
            r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        ).with_confidence(0.90).with_validator("validate_ssn").with_risk_level(PIIRiskLevel::Critical));

        // Credit card patterns
        set.add(Pattern::new(
            "credit_card_visa",
            PIIType::CreditCard,
            r"\b4[0-9]{12}(?:[0-9]{3})?\b",
        ).with_confidence(0.90).with_validator("validate_luhn").with_risk_level(PIIRiskLevel::Critical));

        set.add(Pattern::new(
            "credit_card_mc",
            PIIType::CreditCard,
            r"\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b",
        ).with_confidence(0.90).with_validator("validate_luhn").with_risk_level(PIIRiskLevel::Critical));

        set.add(Pattern::new(
            "credit_card_amex",
            PIIType::CreditCard,
            r"\b3[47][0-9]{13}\b",
        ).with_confidence(0.90).with_validator("validate_luhn").with_risk_level(PIIRiskLevel::Critical));

        set.add(Pattern::new(
            "credit_card_generic",
            PIIType::CreditCard,
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        ).with_confidence(0.75).with_validator("validate_luhn").with_risk_level(PIIRiskLevel::Critical));

        // IP addresses
        set.add(Pattern::new(
            "ipv4",
            PIIType::IpAddress,
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        ).with_confidence(0.95).with_risk_level(PIIRiskLevel::Low));

        set.add(Pattern::new(
            "ipv6",
            PIIType::IpAddress,
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
        ).with_confidence(0.95).with_risk_level(PIIRiskLevel::Low));

        // MAC address (use IpAddress type for network identifiers)
        set.add(Pattern::new(
            "mac_address",
            PIIType::IpAddress,
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
        ).with_confidence(0.95).with_risk_level(PIIRiskLevel::Low));

        // Date of birth patterns
        set.add(Pattern::new(
            "dob_us",
            PIIType::DateOfBirth,
            r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b",
        ).with_confidence(0.70).with_risk_level(PIIRiskLevel::Medium));

        set.add(Pattern::new(
            "dob_iso",
            PIIType::DateOfBirth,
            r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12][0-9]|3[01])\b",
        ).with_confidence(0.70).with_risk_level(PIIRiskLevel::Medium));

        // US Driver's License (generic pattern)
        set.add(Pattern::new(
            "drivers_license",
            PIIType::DriversLicense,
            r"\b[A-Z]{1,2}\d{5,8}\b",
        ).with_confidence(0.50).with_risk_level(PIIRiskLevel::High));

        // Passport number
        set.add(Pattern::new(
            "passport_us",
            PIIType::PassportNumber,
            r"\b[A-Z]\d{8}\b",
        ).with_confidence(0.60).with_risk_level(PIIRiskLevel::High));

        // Bank account (generic)
        set.add(Pattern::new(
            "bank_account_iban",
            PIIType::BankAccount,
            r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b",
        ).with_confidence(0.85).with_risk_level(PIIRiskLevel::High));

        set.add(Pattern::new(
            "bank_routing_us",
            PIIType::BankAccount,
            r"\b\d{9}\b",
        ).with_confidence(0.40).with_validator("validate_routing").with_risk_level(PIIRiskLevel::High));

        // API keys (common formats)
        set.add(Pattern::new(
            "api_key_generic",
            PIIType::ApiKey,
            r#"\b(?:api[_-]?key|apikey|api_secret)[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?"#,
        ).with_confidence(0.80).with_risk_level(PIIRiskLevel::Critical));

        set.add(Pattern::new(
            "aws_key",
            PIIType::ApiKey,
            r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        ).with_confidence(0.95).with_risk_level(PIIRiskLevel::Critical));

        // Passwords in common contexts
        set.add(Pattern::new(
            "password_field",
            PIIType::Password,
            r#"(?i)(?:password|passwd|pwd)[=:]\s*['"]?([^'"\s]{4,})['"]?"#,
        ).with_confidence(0.85).with_risk_level(PIIRiskLevel::Critical));

        // GPS Coordinates
        set.add(Pattern::new(
            "gps_coords",
            PIIType::Coordinates,
            r"\b[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?),\s*[-+]?(?:180(?:\.0+)?|(?:(?:1[0-7]\d)|(?:[1-9]?\d))(?:\.\d+)?)\b",
        ).with_confidence(0.70).with_risk_level(PIIRiskLevel::Medium));

        set
    }

    /// Adds a pattern to the set.
    pub fn add(&mut self, pattern: Pattern) {
        match CompiledPattern::compile(pattern.clone()) {
            Ok(compiled) => {
                let idx = self.patterns.len();
                self.by_type
                    .entry(pattern.pii_type.clone())
                    .or_default()
                    .push(idx);
                self.patterns.push(compiled);
            }
            Err(e) => {
                tracing::warn!("Failed to compile pattern '{}': {}", pattern.name, e);
            }
        }
    }

    /// Finds all matches in text.
    pub fn find_all(&self, text: &str) -> Vec<PatternMatch> {
        let mut matches: Vec<PatternMatch> = self
            .patterns
            .iter()
            .flat_map(|p| p.find_matches(text))
            .collect();

        // Sort by position, then by confidence
        matches.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap())
        });

        // Remove overlapping matches (keep highest confidence)
        let mut filtered = Vec::new();
        let mut last_end = 0;

        for m in matches {
            if m.start >= last_end {
                last_end = m.end;
                filtered.push(m);
            }
        }

        filtered
    }

    /// Finds matches for a specific PII type.
    pub fn find_by_type(&self, text: &str, pii_type: &PIIType) -> Vec<PatternMatch> {
        if let Some(indices) = self.by_type.get(pii_type) {
            indices
                .iter()
                .flat_map(|&i| self.patterns[i].find_matches(text))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Returns the number of patterns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns true if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

impl Default for PatternSet {
    fn default() -> Self {
        Self::new()
    }
}

/// Pattern matcher with validation.
pub struct PatternMatcher {
    patterns: PatternSet,
    validators: HashMap<String, Box<dyn Fn(&str) -> bool + Send + Sync>>,
}

impl PatternMatcher {
    /// Creates a new pattern matcher with built-in patterns.
    #[must_use]
    pub fn new() -> Self {
        let mut matcher = Self {
            patterns: PatternSet::builtin(),
            validators: HashMap::new(),
        };

        // Register built-in validators
        matcher.register_validator("validate_luhn", validate_luhn);
        matcher.register_validator("validate_ssn", validate_ssn);
        matcher.register_validator("validate_routing", validate_routing_number);

        matcher
    }

    /// Creates with custom patterns.
    pub fn with_patterns(patterns: PatternSet) -> Self {
        Self {
            patterns,
            validators: HashMap::new(),
        }
    }

    /// Registers a validator function.
    pub fn register_validator<F>(&mut self, name: &str, validator: F)
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.validators.insert(name.to_string(), Box::new(validator));
    }

    /// Finds and validates all matches.
    pub fn find_validated(&self, text: &str) -> Vec<PatternMatch> {
        let matches = self.patterns.find_all(text);

        matches
            .into_iter()
            .filter(|m| {
                // Find the pattern and check its validator
                let pattern = self
                    .patterns
                    .patterns
                    .iter()
                    .find(|p| p.pattern.name == m.pattern_name);

                if let Some(p) = pattern {
                    if let Some(ref validator_name) = p.pattern.validator {
                        if let Some(validator) = self.validators.get(validator_name) {
                            return validator(&m.matched_text);
                        }
                    }
                }
                true // No validator = pass
            })
            .collect()
    }

    /// Adds a custom pattern.
    pub fn add_pattern(&mut self, pattern: Pattern) {
        self.patterns.add(pattern);
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates a credit card number using the Luhn algorithm.
pub fn validate_luhn(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    sum % 10 == 0
}

/// Validates a US SSN format.
pub fn validate_ssn(ssn: &str) -> bool {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 9 {
        return false;
    }

    let area: u32 = digits[0..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..9].parse().unwrap_or(0);

    // Invalid patterns
    if area == 0 || area == 666 || (area >= 900 && area <= 999) {
        return false;
    }
    if group == 0 {
        return false;
    }
    if serial == 0 {
        return false;
    }

    true
}

/// Validates a US bank routing number.
pub fn validate_routing_number(routing: &str) -> bool {
    let digits: Vec<u32> = routing
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() != 9 {
        return false;
    }

    // Checksum validation
    let checksum = 3 * (digits[0] + digits[3] + digits[6])
        + 7 * (digits[1] + digits[4] + digits[7])
        + (digits[2] + digits[5] + digits[8]);

    checksum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_pattern() {
        let patterns = PatternSet::builtin();
        let matches = patterns.find_by_type("Contact: john.doe@example.com", &PIIType::Email);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_text, "john.doe@example.com");
    }

    #[test]
    fn test_phone_pattern() {
        let patterns = PatternSet::builtin();
        let matches = patterns.find_by_type("Call me at (555) 123-4567", &PIIType::Phone);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_ssn_pattern() {
        let patterns = PatternSet::builtin();
        let matches = patterns.find_by_type("SSN: 123-45-6789", &PIIType::Ssn);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_credit_card_pattern() {
        let patterns = PatternSet::builtin();
        let matches = patterns.find_by_type("Card: 4111111111111111", &PIIType::CreditCard);
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_luhn_validation() {
        assert!(validate_luhn("4111111111111111")); // Valid Visa test card
        assert!(validate_luhn("5500000000000004")); // Valid MC test card
        assert!(!validate_luhn("1234567890123456")); // Invalid
    }

    #[test]
    fn test_ssn_validation() {
        assert!(validate_ssn("123-45-6789"));
        assert!(!validate_ssn("000-45-6789")); // Invalid area
        assert!(!validate_ssn("666-45-6789")); // Invalid area
        assert!(!validate_ssn("123-00-6789")); // Invalid group
    }

    #[test]
    fn test_routing_validation() {
        assert!(validate_routing_number("021000021")); // Chase
        assert!(validate_routing_number("011401533")); // Bank of America
    }

    #[test]
    fn test_pattern_matcher_validated() {
        let matcher = PatternMatcher::new();
        let text = "Valid card: 4111111111111111, Invalid: 1234567890123456";
        let matches = matcher.find_validated(text);

        // Only the valid card should pass Luhn validation
        let card_matches: Vec<_> = matches
            .iter()
            .filter(|m| matches!(m.pii_type, PIIType::CreditCard))
            .collect();

        assert_eq!(card_matches.len(), 1);
        assert!(card_matches[0].matched_text.contains("4111"));
    }
}
