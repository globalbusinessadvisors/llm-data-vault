//! Contextual PII detection.

use crate::{AnonymizeResult, Detection, DetectionMethod, PIIRiskLevel};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use vault_core::record::{PIILocation, PIIType};

/// Anonymization context for tracking state across operations.
#[derive(Debug, Clone, Default)]
pub struct AnonymizationContext {
    /// Dataset ID.
    pub dataset_id: Option<String>,
    /// Tenant ID.
    pub tenant_id: Option<String>,
    /// User ID.
    pub user_id: Option<String>,
    /// Session ID.
    pub session_id: Option<String>,
    /// Custom metadata.
    pub metadata: HashMap<String, String>,
    /// Fields already processed.
    pub processed_fields: HashSet<String>,
    /// Cumulative detections.
    pub detections: Vec<Detection>,
    /// Token mappings.
    pub token_map: HashMap<String, String>,
}

impl AnonymizationContext {
    /// Creates a new context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets dataset ID.
    #[must_use]
    pub fn with_dataset(mut self, dataset_id: impl Into<String>) -> Self {
        self.dataset_id = Some(dataset_id.into());
        self
    }

    /// Sets tenant ID.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Adds metadata.
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Marks a field as processed.
    pub fn mark_processed(&mut self, field: impl Into<String>) {
        self.processed_fields.insert(field.into());
    }

    /// Checks if a field was processed.
    #[must_use]
    pub fn is_processed(&self, field: &str) -> bool {
        self.processed_fields.contains(field)
    }

    /// Adds a detection.
    pub fn add_detection(&mut self, detection: Detection) {
        self.detections.push(detection);
    }

    /// Adds a token mapping.
    pub fn add_token_mapping(&mut self, original: impl Into<String>, token: impl Into<String>) {
        self.token_map.insert(original.into(), token.into());
    }

    /// Gets a token for an original value.
    pub fn get_token(&self, original: &str) -> Option<&String> {
        self.token_map.get(original)
    }

    /// Gets the original value for a token.
    pub fn get_original(&self, token: &str) -> Option<&String> {
        self.token_map
            .iter()
            .find(|(_, t)| *t == token)
            .map(|(o, _)| o)
    }

    /// Clears the context.
    pub fn clear(&mut self) {
        self.processed_fields.clear();
        self.detections.clear();
        self.token_map.clear();
    }
}

/// Context keywords that indicate PII.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextKeyword {
    /// Keyword or phrase.
    pub keyword: String,
    /// PII type it indicates.
    pub pii_type: PIIType,
    /// Confidence boost.
    pub confidence_boost: f64,
    /// Position relative to PII (before, after, around).
    pub position: KeywordPosition,
    /// Max distance from keyword to PII (in chars).
    pub max_distance: usize,
}

/// Position of context keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeywordPosition {
    /// Before the PII.
    Before,
    /// After the PII.
    After,
    /// Either before or after.
    Around,
}

/// Contextual PII detector.
pub struct ContextualDetector {
    keywords: Vec<ContextKeyword>,
    field_indicators: HashMap<String, PIIType>,
}

impl ContextualDetector {
    /// Creates a new contextual detector.
    #[must_use]
    pub fn new() -> Self {
        let mut detector = Self {
            keywords: Vec::new(),
            field_indicators: HashMap::new(),
        };

        // Add built-in context keywords
        detector.add_builtin_keywords();
        detector.add_builtin_field_indicators();

        detector
    }

    fn add_builtin_keywords(&mut self) {
        // Email context
        self.keywords.push(ContextKeyword {
            keyword: "email".to_string(),
            pii_type: PIIType::Email,
            confidence_boost: 0.15,
            position: KeywordPosition::Before,
            max_distance: 50,
        });
        self.keywords.push(ContextKeyword {
            keyword: "e-mail".to_string(),
            pii_type: PIIType::Email,
            confidence_boost: 0.15,
            position: KeywordPosition::Before,
            max_distance: 50,
        });

        // Phone context
        self.keywords.push(ContextKeyword {
            keyword: "phone".to_string(),
            pii_type: PIIType::Phone,
            confidence_boost: 0.2,
            position: KeywordPosition::Before,
            max_distance: 50,
        });
        self.keywords.push(ContextKeyword {
            keyword: "tel".to_string(),
            pii_type: PIIType::Phone,
            confidence_boost: 0.15,
            position: KeywordPosition::Before,
            max_distance: 30,
        });
        self.keywords.push(ContextKeyword {
            keyword: "mobile".to_string(),
            pii_type: PIIType::Phone,
            confidence_boost: 0.2,
            position: KeywordPosition::Before,
            max_distance: 50,
        });
        self.keywords.push(ContextKeyword {
            keyword: "call".to_string(),
            pii_type: PIIType::Phone,
            confidence_boost: 0.1,
            position: KeywordPosition::Before,
            max_distance: 30,
        });

        // SSN context
        self.keywords.push(ContextKeyword {
            keyword: "ssn".to_string(),
            pii_type: PIIType::Ssn,
            confidence_boost: 0.3,
            position: KeywordPosition::Before,
            max_distance: 30,
        });
        self.keywords.push(ContextKeyword {
            keyword: "social security".to_string(),
            pii_type: PIIType::Ssn,
            confidence_boost: 0.3,
            position: KeywordPosition::Before,
            max_distance: 50,
        });

        // Credit card context
        self.keywords.push(ContextKeyword {
            keyword: "card".to_string(),
            pii_type: PIIType::CreditCard,
            confidence_boost: 0.15,
            position: KeywordPosition::Before,
            max_distance: 50,
        });
        self.keywords.push(ContextKeyword {
            keyword: "credit".to_string(),
            pii_type: PIIType::CreditCard,
            confidence_boost: 0.2,
            position: KeywordPosition::Before,
            max_distance: 50,
        });
        self.keywords.push(ContextKeyword {
            keyword: "payment".to_string(),
            pii_type: PIIType::CreditCard,
            confidence_boost: 0.15,
            position: KeywordPosition::Before,
            max_distance: 50,
        });

        // Name context
        self.keywords.push(ContextKeyword {
            keyword: "name".to_string(),
            pii_type: PIIType::Name,
            confidence_boost: 0.15,
            position: KeywordPosition::Before,
            max_distance: 30,
        });
        self.keywords.push(ContextKeyword {
            keyword: "mr.".to_string(),
            pii_type: PIIType::Name,
            confidence_boost: 0.2,
            position: KeywordPosition::Before,
            max_distance: 10,
        });
        self.keywords.push(ContextKeyword {
            keyword: "ms.".to_string(),
            pii_type: PIIType::Name,
            confidence_boost: 0.2,
            position: KeywordPosition::Before,
            max_distance: 10,
        });
        self.keywords.push(ContextKeyword {
            keyword: "dr.".to_string(),
            pii_type: PIIType::Name,
            confidence_boost: 0.2,
            position: KeywordPosition::Before,
            max_distance: 10,
        });

        // Address context
        self.keywords.push(ContextKeyword {
            keyword: "address".to_string(),
            pii_type: PIIType::Address,
            confidence_boost: 0.2,
            position: KeywordPosition::Before,
            max_distance: 50,
        });
        self.keywords.push(ContextKeyword {
            keyword: "street".to_string(),
            pii_type: PIIType::Address,
            confidence_boost: 0.15,
            position: KeywordPosition::Around,
            max_distance: 100,
        });

        // Date of birth context
        self.keywords.push(ContextKeyword {
            keyword: "dob".to_string(),
            pii_type: PIIType::DateOfBirth,
            confidence_boost: 0.3,
            position: KeywordPosition::Before,
            max_distance: 30,
        });
        self.keywords.push(ContextKeyword {
            keyword: "birth".to_string(),
            pii_type: PIIType::DateOfBirth,
            confidence_boost: 0.25,
            position: KeywordPosition::Before,
            max_distance: 50,
        });
        self.keywords.push(ContextKeyword {
            keyword: "born".to_string(),
            pii_type: PIIType::DateOfBirth,
            confidence_boost: 0.2,
            position: KeywordPosition::Before,
            max_distance: 50,
        });

        // Password context
        self.keywords.push(ContextKeyword {
            keyword: "password".to_string(),
            pii_type: PIIType::Password,
            confidence_boost: 0.4,
            position: KeywordPosition::Before,
            max_distance: 30,
        });
        self.keywords.push(ContextKeyword {
            keyword: "pwd".to_string(),
            pii_type: PIIType::Password,
            confidence_boost: 0.3,
            position: KeywordPosition::Before,
            max_distance: 20,
        });

        // API key context
        self.keywords.push(ContextKeyword {
            keyword: "api_key".to_string(),
            pii_type: PIIType::ApiKey,
            confidence_boost: 0.4,
            position: KeywordPosition::Before,
            max_distance: 30,
        });
        self.keywords.push(ContextKeyword {
            keyword: "secret".to_string(),
            pii_type: PIIType::ApiKey,
            confidence_boost: 0.25,
            position: KeywordPosition::Before,
            max_distance: 30,
        });
    }

    fn add_builtin_field_indicators(&mut self) {
        // Common field names that indicate PII
        self.field_indicators.insert("email".to_string(), PIIType::Email);
        self.field_indicators.insert("email_address".to_string(), PIIType::Email);
        self.field_indicators.insert("user_email".to_string(), PIIType::Email);

        self.field_indicators.insert("phone".to_string(), PIIType::Phone);
        self.field_indicators.insert("phone_number".to_string(), PIIType::Phone);
        self.field_indicators.insert("mobile".to_string(), PIIType::Phone);
        self.field_indicators.insert("tel".to_string(), PIIType::Phone);

        self.field_indicators.insert("ssn".to_string(), PIIType::Ssn);
        self.field_indicators.insert("social_security".to_string(), PIIType::Ssn);
        self.field_indicators.insert("social_security_number".to_string(), PIIType::Ssn);

        self.field_indicators.insert("name".to_string(), PIIType::Name);
        self.field_indicators.insert("full_name".to_string(), PIIType::Name);
        self.field_indicators.insert("first_name".to_string(), PIIType::Name);
        self.field_indicators.insert("last_name".to_string(), PIIType::Name);

        self.field_indicators.insert("address".to_string(), PIIType::Address);
        self.field_indicators.insert("street_address".to_string(), PIIType::Address);
        self.field_indicators.insert("home_address".to_string(), PIIType::Address);

        self.field_indicators.insert("credit_card".to_string(), PIIType::CreditCard);
        self.field_indicators.insert("card_number".to_string(), PIIType::CreditCard);
        self.field_indicators.insert("cc_number".to_string(), PIIType::CreditCard);

        self.field_indicators.insert("dob".to_string(), PIIType::DateOfBirth);
        self.field_indicators.insert("date_of_birth".to_string(), PIIType::DateOfBirth);
        self.field_indicators.insert("birthdate".to_string(), PIIType::DateOfBirth);

        self.field_indicators.insert("ip".to_string(), PIIType::IpAddress);
        self.field_indicators.insert("ip_address".to_string(), PIIType::IpAddress);
        self.field_indicators.insert("client_ip".to_string(), PIIType::IpAddress);

        self.field_indicators.insert("password".to_string(), PIIType::Password);
        self.field_indicators.insert("passwd".to_string(), PIIType::Password);
        self.field_indicators.insert("pwd".to_string(), PIIType::Password);

        self.field_indicators.insert("api_key".to_string(), PIIType::ApiKey);
        self.field_indicators.insert("apikey".to_string(), PIIType::ApiKey);
        self.field_indicators.insert("secret_key".to_string(), PIIType::ApiKey);
    }

    /// Adds a context keyword.
    pub fn add_keyword(&mut self, keyword: ContextKeyword) {
        self.keywords.push(keyword);
    }

    /// Adds a field indicator.
    pub fn add_field_indicator(&mut self, field: impl Into<String>, pii_type: PIIType) {
        self.field_indicators.insert(field.into(), pii_type);
    }

    /// Analyzes context around a potential detection.
    pub fn analyze_context(
        &self,
        text: &str,
        start: usize,
        end: usize,
        base_pii_type: &PIIType,
    ) -> ContextAnalysis {
        let mut analysis = ContextAnalysis {
            confidence_boost: 0.0,
            suggested_type: None,
            keywords_found: Vec::new(),
        };

        let text_lower = text.to_lowercase();

        for keyword in &self.keywords {
            let keyword_lower = keyword.keyword.to_lowercase();

            // Search for keyword in appropriate position
            let found = match keyword.position {
                KeywordPosition::Before => {
                    let search_start = start.saturating_sub(keyword.max_distance);
                    text_lower[search_start..start].contains(&keyword_lower)
                }
                KeywordPosition::After => {
                    let search_end = (end + keyword.max_distance).min(text.len());
                    text_lower[end..search_end].contains(&keyword_lower)
                }
                KeywordPosition::Around => {
                    let search_start = start.saturating_sub(keyword.max_distance);
                    let search_end = (end + keyword.max_distance).min(text.len());
                    text_lower[search_start..start].contains(&keyword_lower)
                        || text_lower[end..search_end].contains(&keyword_lower)
                }
            };

            if found {
                analysis.keywords_found.push(keyword.keyword.clone());

                if keyword.pii_type == *base_pii_type {
                    analysis.confidence_boost += keyword.confidence_boost;
                } else if analysis.suggested_type.is_none() {
                    analysis.suggested_type = Some(keyword.pii_type.clone());
                }
            }
        }

        // Cap confidence boost
        analysis.confidence_boost = analysis.confidence_boost.min(0.4);

        analysis
    }

    /// Gets PII type hint from field name.
    pub fn type_from_field(&self, field_name: &str) -> Option<&PIIType> {
        let normalized = field_name.to_lowercase().replace(['-', ' '], "_");
        self.field_indicators.get(&normalized)
    }

    /// Detects PII based purely on context (for unstructured text).
    pub fn detect_from_context(&self, text: &str) -> Vec<Detection> {
        let text_lower = text.to_lowercase();
        let mut detections = Vec::new();

        for keyword in &self.keywords {
            let keyword_lower = keyword.keyword.to_lowercase();

            // Find all occurrences of the keyword
            for (pos, _) in text_lower.match_indices(&keyword_lower) {
                // Look for potential PII after the keyword
                let search_start = pos + keyword.keyword.len();
                let search_end = (search_start + keyword.max_distance).min(text.len());

                if search_start < search_end {
                    let potential_pii = &text[search_start..search_end];

                    // Try to extract a value (simple heuristic)
                    if let Some(value) = self.extract_value(potential_pii) {
                        detections.push(Detection {
                            pii_type: keyword.pii_type.clone(),
                            location: PIILocation::ByteRange {
                                start: search_start + value.0,
                                end: search_start + value.1,
                            },
                            value: value.2,
                            confidence: 0.5 + keyword.confidence_boost,
                            risk_level: PIIRiskLevel::Medium,
                            method: DetectionMethod::Contextual,
                            context: Some(text[pos..search_end].to_string()),
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }

        detections
    }

    /// Extracts a potential value after a keyword.
    fn extract_value(&self, text: &str) -> Option<(usize, usize, String)> {
        // Skip common separators
        let skip_chars = [':', '=', ' ', '\t', '"', '\''];
        let start = text.chars().take_while(|c| skip_chars.contains(c)).count();

        if start >= text.len() {
            return None;
        }

        let remaining = &text[start..];

        // Find end of value (whitespace, comma, or end of string)
        let end = remaining
            .char_indices()
            .find(|(_, c)| c.is_whitespace() || *c == ',' || *c == '"' || *c == '\'')
            .map(|(i, _)| i)
            .unwrap_or(remaining.len());

        if end > 0 {
            Some((start, start + end, remaining[..end].to_string()))
        } else {
            None
        }
    }
}

impl Default for ContextualDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of context analysis.
#[derive(Debug, Clone)]
pub struct ContextAnalysis {
    /// Confidence boost from context.
    pub confidence_boost: f64,
    /// Suggested PII type if different from base.
    pub suggested_type: Option<PIIType>,
    /// Keywords found in context.
    pub keywords_found: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_keywords() {
        let detector = ContextualDetector::new();

        // Test email context
        let text = "Contact email: john@example.com for info";
        let analysis = detector.analyze_context(text, 15, 31, &PIIType::Email);

        assert!(analysis.confidence_boost > 0.0);
        assert!(analysis.keywords_found.contains(&"email".to_string()));
    }

    #[test]
    fn test_field_indicators() {
        let detector = ContextualDetector::new();

        assert_eq!(
            detector.type_from_field("email_address"),
            Some(&PIIType::Email)
        );
        assert_eq!(
            detector.type_from_field("phone_number"),
            Some(&PIIType::Phone)
        );
        assert_eq!(
            detector.type_from_field("user-email"),
            Some(&PIIType::Email)
        );
    }

    #[test]
    fn test_context_detection() {
        let detector = ContextualDetector::new();
        let text = "password: secret123 for the account";

        let detections = detector.detect_from_context(text);

        assert!(!detections.is_empty());
        assert!(detections.iter().any(|d| matches!(d.pii_type, PIIType::Password)));
    }

    #[test]
    fn test_anonymization_context() {
        let mut ctx = AnonymizationContext::new()
            .with_dataset("ds-123")
            .with_tenant("tenant-456");

        ctx.add_token_mapping("secret@email.com", "TOK_abc123");
        ctx.mark_processed("user.email");

        assert!(ctx.is_processed("user.email"));
        assert!(!ctx.is_processed("user.name"));
        assert_eq!(ctx.get_token("secret@email.com"), Some(&"TOK_abc123".to_string()));
    }
}
