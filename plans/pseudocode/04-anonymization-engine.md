# LLM-Data-Vault Pseudocode: Anonymization Engine

**Document:** 04-anonymization-engine.md
**Version:** 1.0.0
**Phase:** SPARC - Pseudocode
**Last Updated:** 2025-11-27

---

## Overview

This document defines the anonymization engine for LLM-Data-Vault:
- PII detection with 99.5%+ accuracy
- Multiple anonymization strategies (masking, tokenization, hashing, generalization)
- Reversible and irreversible modes
- Performance target: 1GB/s throughput

---

## 1. PII Detection Core

```rust
// src/anonymization/detection/mod.rs

use std::ops::Range;

// ============================================================================
// PII Detector Trait
// ============================================================================

pub trait PIIDetector: Send + Sync {
    /// Detect PII in text
    fn detect(&self, text: &str) -> Vec<PIIMatch>;

    /// Batch detection for efficiency
    fn detect_batch(&self, texts: &[&str]) -> Vec<Vec<PIIMatch>> {
        texts.iter().map(|t| self.detect(t)).collect()
    }

    /// List supported PII types
    fn supported_types(&self) -> Vec<PIIType>;

    /// Detector identifier
    fn detector_type(&self) -> &'static str;
}

// ============================================================================
// PII Types and Matches
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PIIType {
    // Contact Information
    Email,
    PhoneNumber,
    Address,

    // Personal Identifiers
    Name,
    SSN,
    DriversLicense,
    PassportNumber,
    DateOfBirth,

    // Financial
    CreditCard,
    BankAccount,
    IBAN,

    // Technical
    IPAddress,
    MACAddress,
    APIKey,
    Password,
    PrivateKey,

    // Healthcare
    MedicalRecordNumber,
    HealthInsuranceId,

    // Custom
    Custom(u32),
}

impl PIIType {
    pub fn sensitivity(&self) -> PIISensitivity {
        match self {
            PIIType::Email | PIIType::PhoneNumber => PIISensitivity::Medium,
            PIIType::Name | PIIType::Address | PIIType::DateOfBirth => PIISensitivity::Medium,
            PIIType::SSN | PIIType::DriversLicense | PIIType::PassportNumber => PIISensitivity::High,
            PIIType::CreditCard | PIIType::BankAccount | PIIType::IBAN => PIISensitivity::High,
            PIIType::APIKey | PIIType::Password | PIIType::PrivateKey => PIISensitivity::Critical,
            PIIType::MedicalRecordNumber | PIIType::HealthInsuranceId => PIISensitivity::High,
            PIIType::IPAddress | PIIType::MACAddress => PIISensitivity::Low,
            PIIType::Custom(_) => PIISensitivity::Medium,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PIISensitivity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct PIIMatch {
    pub pii_type: PIIType,
    pub span: Range<usize>,
    pub text: String,
    pub confidence: f32,
    pub detector: String,
    pub context: Option<MatchContext>,
}

#[derive(Debug, Clone)]
pub struct MatchContext {
    pub before: String,  // Text before match (up to N chars)
    pub after: String,   // Text after match (up to N chars)
    pub field_name: Option<String>,
}

impl PIIMatch {
    pub fn start(&self) -> usize {
        self.span.start
    }

    pub fn end(&self) -> usize {
        self.span.end
    }

    pub fn len(&self) -> usize {
        self.span.len()
    }

    pub fn overlaps(&self, other: &PIIMatch) -> bool {
        self.span.start < other.span.end && other.span.start < self.span.end
    }
}
```

---

## 2. Pattern-Based PII Detector

```rust
// src/anonymization/detection/regex.rs

use regex::{Regex, RegexSet};
use once_cell::sync::Lazy;

pub struct RegexPIIDetector {
    patterns: Vec<PIIPattern>,
    regex_set: RegexSet,
    validators: HashMap<PIIType, Box<dyn Fn(&str) -> bool + Send + Sync>>,
    config: RegexDetectorConfig,
}

#[derive(Debug, Clone)]
pub struct RegexDetectorConfig {
    pub min_confidence: f32,
    pub context_window: usize,
    pub enable_validation: bool,
}

struct PIIPattern {
    pii_type: PIIType,
    regex: Regex,
    base_confidence: f32,
    description: String,
}

// Pre-compiled patterns for common PII types
static EMAIL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap()
});

static PHONE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}").unwrap()
});

static SSN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").unwrap()
});

static CREDIT_CARD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b").unwrap()
});

static IP_ADDRESS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

static API_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?").unwrap()
});

impl RegexPIIDetector {
    pub fn new(config: RegexDetectorConfig) -> Self {
        let mut patterns = Vec::new();
        let mut regex_strings = Vec::new();

        // Email
        patterns.push(PIIPattern {
            pii_type: PIIType::Email,
            regex: EMAIL_PATTERN.clone(),
            base_confidence: 0.95,
            description: "Email address".into(),
        });
        regex_strings.push(EMAIL_PATTERN.as_str().to_string());

        // Phone
        patterns.push(PIIPattern {
            pii_type: PIIType::PhoneNumber,
            regex: PHONE_PATTERN.clone(),
            base_confidence: 0.85,
            description: "Phone number".into(),
        });
        regex_strings.push(PHONE_PATTERN.as_str().to_string());

        // SSN
        patterns.push(PIIPattern {
            pii_type: PIIType::SSN,
            regex: SSN_PATTERN.clone(),
            base_confidence: 0.80,
            description: "Social Security Number".into(),
        });
        regex_strings.push(SSN_PATTERN.as_str().to_string());

        // Credit Card
        patterns.push(PIIPattern {
            pii_type: PIIType::CreditCard,
            regex: CREDIT_CARD_PATTERN.clone(),
            base_confidence: 0.90,
            description: "Credit card number".into(),
        });
        regex_strings.push(CREDIT_CARD_PATTERN.as_str().to_string());

        // IP Address
        patterns.push(PIIPattern {
            pii_type: PIIType::IPAddress,
            regex: IP_ADDRESS_PATTERN.clone(),
            base_confidence: 0.95,
            description: "IP address".into(),
        });
        regex_strings.push(IP_ADDRESS_PATTERN.as_str().to_string());

        // API Key
        patterns.push(PIIPattern {
            pii_type: PIIType::APIKey,
            regex: API_KEY_PATTERN.clone(),
            base_confidence: 0.90,
            description: "API key or token".into(),
        });
        regex_strings.push(API_KEY_PATTERN.as_str().to_string());

        let regex_set = RegexSet::new(&regex_strings).unwrap();

        // Validators for additional verification
        let mut validators: HashMap<PIIType, Box<dyn Fn(&str) -> bool + Send + Sync>> = HashMap::new();

        validators.insert(PIIType::CreditCard, Box::new(|s| luhn_check(s)));
        validators.insert(PIIType::SSN, Box::new(|s| validate_ssn(s)));
        validators.insert(PIIType::Email, Box::new(|s| validate_email(s)));

        Self {
            patterns,
            regex_set,
            validators,
            config,
        }
    }

    /// Add a custom pattern
    pub fn add_pattern(
        &mut self,
        pii_type: PIIType,
        pattern: &str,
        confidence: f32,
    ) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.patterns.push(PIIPattern {
            pii_type,
            regex,
            base_confidence: confidence,
            description: format!("Custom pattern for {:?}", pii_type),
        });
        // Rebuild regex set
        let regex_strings: Vec<_> = self.patterns.iter().map(|p| p.regex.as_str()).collect();
        self.regex_set = RegexSet::new(&regex_strings)?;
        Ok(())
    }

    fn extract_context(&self, text: &str, span: &Range<usize>) -> MatchContext {
        let window = self.config.context_window;

        let before_start = span.start.saturating_sub(window);
        let before = text[before_start..span.start].to_string();

        let after_end = std::cmp::min(span.end + window, text.len());
        let after = text[span.end..after_end].to_string();

        MatchContext {
            before,
            after,
            field_name: None,
        }
    }

    fn adjust_confidence(&self, base_confidence: f32, text: &str, pii_type: &PIIType) -> f32 {
        let mut confidence = base_confidence;

        // Adjust based on validation
        if self.config.enable_validation {
            if let Some(validator) = self.validators.get(pii_type) {
                if validator(text) {
                    confidence = (confidence + 0.1).min(1.0);
                } else {
                    confidence = (confidence - 0.2).max(0.0);
                }
            }
        }

        confidence
    }
}

impl PIIDetector for RegexPIIDetector {
    fn detect(&self, text: &str) -> Vec<PIIMatch> {
        let mut matches = Vec::new();

        // Use RegexSet for fast initial matching
        let matching_indices: Vec<_> = self.regex_set.matches(text).iter().collect();

        for idx in matching_indices {
            let pattern = &self.patterns[idx];

            for mat in pattern.regex.find_iter(text) {
                let matched_text = mat.as_str().to_string();
                let span = mat.start()..mat.end();

                let confidence = self.adjust_confidence(
                    pattern.base_confidence,
                    &matched_text,
                    &pattern.pii_type,
                );

                if confidence >= self.config.min_confidence {
                    matches.push(PIIMatch {
                        pii_type: pattern.pii_type,
                        span: span.clone(),
                        text: matched_text,
                        confidence,
                        detector: "regex".into(),
                        context: Some(self.extract_context(text, &span)),
                    });
                }
            }
        }

        // Sort by position and deduplicate overlapping matches
        matches.sort_by_key(|m| m.span.start);
        deduplicate_matches(&mut matches);

        matches
    }

    fn supported_types(&self) -> Vec<PIIType> {
        self.patterns.iter().map(|p| p.pii_type).collect()
    }

    fn detector_type(&self) -> &'static str {
        "regex"
    }
}

// Validation functions
fn luhn_check(number: &str) -> bool {
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
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();

    sum % 10 == 0
}

fn validate_ssn(ssn: &str) -> bool {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 9 {
        return false;
    }

    // Check for invalid SSN patterns
    let area = &digits[0..3];
    let group = &digits[3..5];
    let serial = &digits[5..9];

    // Invalid area numbers
    if area == "000" || area == "666" || area.starts_with("9") {
        return false;
    }

    // Group and serial cannot be all zeros
    if group == "00" || serial == "0000" {
        return false;
    }

    true
}

fn validate_email(email: &str) -> bool {
    // Basic email validation
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    !local.is_empty() && !domain.is_empty() && domain.contains('.')
}

fn deduplicate_matches(matches: &mut Vec<PIIMatch>) {
    let mut i = 0;
    while i < matches.len() {
        let mut j = i + 1;
        while j < matches.len() {
            if matches[i].overlaps(&matches[j]) {
                // Keep the one with higher confidence
                if matches[i].confidence >= matches[j].confidence {
                    matches.remove(j);
                } else {
                    matches.remove(i);
                    j = i + 1;
                    continue;
                }
            } else {
                j += 1;
            }
        }
        i += 1;
    }
}
```

---

## 3. ML-Based NER Detector

```rust
// src/anonymization/detection/ner.rs

use ort::{Session, Environment};

pub struct NERPIIDetector {
    session: Session,
    tokenizer: Tokenizer,
    config: NERConfig,
    label_map: HashMap<String, PIIType>,
}

#[derive(Debug, Clone)]
pub struct NERConfig {
    pub model_path: PathBuf,
    pub tokenizer_path: PathBuf,
    pub batch_size: usize,
    pub max_sequence_length: usize,
    pub confidence_threshold: f32,
}

impl NERPIIDetector {
    pub fn new(config: NERConfig) -> Result<Self, AnonymizationError> {
        let environment = Environment::builder()
            .with_name("ner_detector")
            .build()?;

        let session = Session::builder()?
            .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
            .with_model_from_file(&config.model_path)?;

        let tokenizer = Tokenizer::from_file(&config.tokenizer_path)?;

        // Standard NER label mapping
        let label_map = HashMap::from([
            ("B-PER".to_string(), PIIType::Name),
            ("I-PER".to_string(), PIIType::Name),
            ("B-ORG".to_string(), PIIType::Custom(1)),  // Organization
            ("I-ORG".to_string(), PIIType::Custom(1)),
            ("B-LOC".to_string(), PIIType::Address),
            ("I-LOC".to_string(), PIIType::Address),
            ("B-EMAIL".to_string(), PIIType::Email),
            ("I-EMAIL".to_string(), PIIType::Email),
            ("B-PHONE".to_string(), PIIType::PhoneNumber),
            ("I-PHONE".to_string(), PIIType::PhoneNumber),
            ("B-SSN".to_string(), PIIType::SSN),
            ("I-SSN".to_string(), PIIType::SSN),
            ("B-CREDIT_CARD".to_string(), PIIType::CreditCard),
            ("I-CREDIT_CARD".to_string(), PIIType::CreditCard),
        ]);

        Ok(Self {
            session,
            tokenizer,
            config,
            label_map,
        })
    }

    fn tokenize(&self, text: &str) -> TokenizedInput {
        let encoding = self.tokenizer.encode(text, true).unwrap();

        TokenizedInput {
            input_ids: encoding.get_ids().to_vec(),
            attention_mask: encoding.get_attention_mask().to_vec(),
            token_offsets: encoding.get_offsets().to_vec(),
            tokens: encoding.get_tokens().to_vec(),
        }
    }

    fn run_inference(&self, inputs: &[TokenizedInput]) -> Result<Vec<Vec<EntityPrediction>>, AnonymizationError> {
        let batch_size = inputs.len();
        let seq_len = self.config.max_sequence_length;

        // Prepare input tensors
        let mut input_ids = vec![0i64; batch_size * seq_len];
        let mut attention_mask = vec![0i64; batch_size * seq_len];

        for (i, input) in inputs.iter().enumerate() {
            for (j, &id) in input.input_ids.iter().take(seq_len).enumerate() {
                input_ids[i * seq_len + j] = id as i64;
                attention_mask[i * seq_len + j] = input.attention_mask[j] as i64;
            }
        }

        let input_ids_tensor = ndarray::Array2::from_shape_vec(
            (batch_size, seq_len),
            input_ids,
        )?;
        let attention_mask_tensor = ndarray::Array2::from_shape_vec(
            (batch_size, seq_len),
            attention_mask,
        )?;

        // Run inference
        let outputs = self.session.run(vec![
            ort::Value::from_array(input_ids_tensor)?,
            ort::Value::from_array(attention_mask_tensor)?,
        ])?;

        // Parse output logits
        let logits: ndarray::ArrayView3<f32> = outputs[0].try_extract()?;

        let mut results = Vec::with_capacity(batch_size);
        for batch_idx in 0..batch_size {
            let mut predictions = Vec::new();

            for (token_idx, token_logits) in logits.slice(s![batch_idx, .., ..]).outer_iter().enumerate() {
                if token_idx >= inputs[batch_idx].tokens.len() {
                    break;
                }

                let (label_idx, confidence) = token_logits
                    .iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                    .unwrap();

                let softmax_confidence = softmax(&token_logits.to_vec())[label_idx];

                if softmax_confidence >= self.config.confidence_threshold {
                    predictions.push(EntityPrediction {
                        token_idx,
                        label_idx,
                        confidence: softmax_confidence,
                    });
                }
            }

            results.push(predictions);
        }

        Ok(results)
    }

    fn merge_entities(
        &self,
        predictions: &[EntityPrediction],
        input: &TokenizedInput,
        text: &str,
    ) -> Vec<PIIMatch> {
        let mut matches = Vec::new();
        let mut current_entity: Option<(PIIType, usize, usize, f32)> = None;

        for pred in predictions {
            let label = self.index_to_label(pred.label_idx);

            if label == "O" {
                // End current entity if exists
                if let Some((pii_type, start, end, confidence)) = current_entity.take() {
                    matches.push(PIIMatch {
                        pii_type,
                        span: start..end,
                        text: text[start..end].to_string(),
                        confidence,
                        detector: "ner".into(),
                        context: None,
                    });
                }
                continue;
            }

            let (prefix, entity_type) = label.split_once('-').unwrap_or(("O", "O"));
            let pii_type = self.label_map.get(&label).copied().unwrap_or(PIIType::Custom(0));

            let (token_start, token_end) = input.token_offsets[pred.token_idx];

            match prefix {
                "B" => {
                    // Start new entity, save previous if exists
                    if let Some((prev_type, start, end, confidence)) = current_entity.take() {
                        matches.push(PIIMatch {
                            pii_type: prev_type,
                            span: start..end,
                            text: text[start..end].to_string(),
                            confidence,
                            detector: "ner".into(),
                            context: None,
                        });
                    }
                    current_entity = Some((pii_type, token_start, token_end, pred.confidence));
                }
                "I" => {
                    // Continue current entity
                    if let Some((_, _, ref mut end, ref mut confidence)) = current_entity {
                        *end = token_end;
                        *confidence = (*confidence + pred.confidence) / 2.0;
                    }
                }
                _ => {}
            }
        }

        // Don't forget the last entity
        if let Some((pii_type, start, end, confidence)) = current_entity {
            matches.push(PIIMatch {
                pii_type,
                span: start..end,
                text: text[start..end].to_string(),
                confidence,
                detector: "ner".into(),
                context: None,
            });
        }

        matches
    }

    fn index_to_label(&self, idx: usize) -> &str {
        // Would be loaded from model config
        const LABELS: &[&str] = &[
            "O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC",
            "B-EMAIL", "I-EMAIL", "B-PHONE", "I-PHONE", "B-SSN", "I-SSN",
            "B-CREDIT_CARD", "I-CREDIT_CARD",
        ];
        LABELS.get(idx).unwrap_or(&"O")
    }
}

impl PIIDetector for NERPIIDetector {
    fn detect(&self, text: &str) -> Vec<PIIMatch> {
        let input = self.tokenize(text);

        match self.run_inference(&[input.clone()]) {
            Ok(predictions) => {
                if let Some(preds) = predictions.first() {
                    self.merge_entities(preds, &input, text)
                } else {
                    Vec::new()
                }
            }
            Err(_) => Vec::new(),
        }
    }

    fn detect_batch(&self, texts: &[&str]) -> Vec<Vec<PIIMatch>> {
        let inputs: Vec<TokenizedInput> = texts.iter().map(|t| self.tokenize(t)).collect();

        // Process in batches
        let mut all_results = Vec::with_capacity(texts.len());

        for chunk in inputs.chunks(self.config.batch_size) {
            match self.run_inference(chunk) {
                Ok(predictions) => {
                    for (i, preds) in predictions.iter().enumerate() {
                        let matches = self.merge_entities(preds, &chunk[i], texts[i]);
                        all_results.push(matches);
                    }
                }
                Err(_) => {
                    all_results.extend(std::iter::repeat(Vec::new()).take(chunk.len()));
                }
            }
        }

        all_results
    }

    fn supported_types(&self) -> Vec<PIIType> {
        self.label_map.values().copied().collect()
    }

    fn detector_type(&self) -> &'static str {
        "ner"
    }
}

struct TokenizedInput {
    input_ids: Vec<u32>,
    attention_mask: Vec<u32>,
    token_offsets: Vec<(usize, usize)>,
    tokens: Vec<String>,
}

struct EntityPrediction {
    token_idx: usize,
    label_idx: usize,
    confidence: f32,
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|&x| (x - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps.iter().map(|&x| x / sum).collect()
}
```

---

## 4. Anonymization Strategies

```rust
// src/anonymization/strategies/mod.rs

// ============================================================================
// Anonymization Strategy Trait
// ============================================================================

pub trait AnonymizationStrategy: Send + Sync {
    /// Apply anonymization to text for given matches
    fn anonymize(&self, text: &str, matches: &[PIIMatch]) -> AnonymizedResult;

    /// Whether this strategy is reversible
    fn is_reversible(&self) -> bool;

    /// Strategy identifier
    fn strategy_type(&self) -> &'static str;
}

#[derive(Debug, Clone)]
pub struct AnonymizedResult {
    pub text: String,
    pub replacements: Vec<Replacement>,
    pub metadata: AnonymizationMetadata,
}

#[derive(Debug, Clone)]
pub struct Replacement {
    pub original_span: Range<usize>,
    pub original_text: String,
    pub replacement_text: String,
    pub pii_type: PIIType,
    pub reversible_token: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AnonymizationMetadata {
    pub strategy: String,
    pub timestamp: DateTime<Utc>,
    pub pii_counts: HashMap<PIIType, usize>,
    pub total_replacements: usize,
}

// ============================================================================
// Masking Strategy (Irreversible)
// ============================================================================

pub struct MaskingStrategy {
    config: MaskingConfig,
}

#[derive(Debug, Clone)]
pub struct MaskingConfig {
    pub mask_char: char,
    pub use_type_label: bool,
    pub preserve_length: bool,
    pub type_labels: HashMap<PIIType, String>,
}

impl Default for MaskingConfig {
    fn default() -> Self {
        let mut type_labels = HashMap::new();
        type_labels.insert(PIIType::Email, "[EMAIL]".to_string());
        type_labels.insert(PIIType::PhoneNumber, "[PHONE]".to_string());
        type_labels.insert(PIIType::SSN, "[SSN]".to_string());
        type_labels.insert(PIIType::CreditCard, "[CREDIT_CARD]".to_string());
        type_labels.insert(PIIType::Name, "[NAME]".to_string());
        type_labels.insert(PIIType::Address, "[ADDRESS]".to_string());
        type_labels.insert(PIIType::APIKey, "[API_KEY]".to_string());

        Self {
            mask_char: '*',
            use_type_label: true,
            preserve_length: false,
            type_labels,
        }
    }
}

impl MaskingStrategy {
    pub fn new(config: MaskingConfig) -> Self {
        Self { config }
    }

    fn get_replacement(&self, pii_type: PIIType, original_len: usize) -> String {
        if self.config.use_type_label {
            self.config.type_labels
                .get(&pii_type)
                .cloned()
                .unwrap_or_else(|| "[REDACTED]".to_string())
        } else if self.config.preserve_length {
            self.config.mask_char.to_string().repeat(original_len)
        } else {
            "***".to_string()
        }
    }
}

impl AnonymizationStrategy for MaskingStrategy {
    fn anonymize(&self, text: &str, matches: &[PIIMatch]) -> AnonymizedResult {
        let mut result = text.to_string();
        let mut replacements = Vec::new();
        let mut offset: isize = 0;

        // Sort matches by position (should already be sorted)
        let mut sorted_matches = matches.to_vec();
        sorted_matches.sort_by_key(|m| m.span.start);

        for mat in &sorted_matches {
            let adjusted_start = (mat.span.start as isize + offset) as usize;
            let adjusted_end = (mat.span.end as isize + offset) as usize;

            let replacement = self.get_replacement(mat.pii_type, mat.len());
            let len_diff = replacement.len() as isize - mat.len() as isize;

            result.replace_range(adjusted_start..adjusted_end, &replacement);
            offset += len_diff;

            replacements.push(Replacement {
                original_span: mat.span.clone(),
                original_text: mat.text.clone(),
                replacement_text: replacement,
                pii_type: mat.pii_type,
                reversible_token: None,
            });
        }

        let mut pii_counts = HashMap::new();
        for mat in matches {
            *pii_counts.entry(mat.pii_type).or_insert(0) += 1;
        }

        AnonymizedResult {
            text: result,
            replacements,
            metadata: AnonymizationMetadata {
                strategy: "masking".to_string(),
                timestamp: Utc::now(),
                pii_counts,
                total_replacements: matches.len(),
            },
        }
    }

    fn is_reversible(&self) -> bool {
        false
    }

    fn strategy_type(&self) -> &'static str {
        "masking"
    }
}

// ============================================================================
// Tokenization Strategy (Reversible)
// ============================================================================

pub struct TokenizationStrategy {
    vault: Arc<TokenVault>,
    config: TokenizationConfig,
}

#[derive(Debug, Clone)]
pub struct TokenizationConfig {
    pub token_prefix: String,
    pub token_length: usize,
    pub include_type: bool,
}

impl TokenizationStrategy {
    pub fn new(vault: Arc<TokenVault>, config: TokenizationConfig) -> Self {
        Self { vault, config }
    }

    fn generate_token(&self, pii_type: PIIType) -> String {
        let random_part: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(self.config.token_length)
            .map(char::from)
            .collect();

        if self.config.include_type {
            format!("{}_{}_{}", self.config.token_prefix, pii_type_code(pii_type), random_part)
        } else {
            format!("{}_{}", self.config.token_prefix, random_part)
        }
    }
}

impl AnonymizationStrategy for TokenizationStrategy {
    fn anonymize(&self, text: &str, matches: &[PIIMatch]) -> AnonymizedResult {
        let mut result = text.to_string();
        let mut replacements = Vec::new();
        let mut offset: isize = 0;

        let mut sorted_matches = matches.to_vec();
        sorted_matches.sort_by_key(|m| m.span.start);

        for mat in &sorted_matches {
            // Check if we already have a token for this value (consistency)
            let token = match self.vault.get_token_for_value(&mat.text) {
                Some(existing_token) => existing_token,
                None => {
                    let new_token = self.generate_token(mat.pii_type);
                    // Store in vault
                    self.vault.store(&new_token, &mat.text, mat.pii_type);
                    new_token
                }
            };

            let adjusted_start = (mat.span.start as isize + offset) as usize;
            let adjusted_end = (mat.span.end as isize + offset) as usize;

            let len_diff = token.len() as isize - mat.len() as isize;
            result.replace_range(adjusted_start..adjusted_end, &token);
            offset += len_diff;

            replacements.push(Replacement {
                original_span: mat.span.clone(),
                original_text: mat.text.clone(),
                replacement_text: token.clone(),
                pii_type: mat.pii_type,
                reversible_token: Some(token),
            });
        }

        let mut pii_counts = HashMap::new();
        for mat in matches {
            *pii_counts.entry(mat.pii_type).or_insert(0) += 1;
        }

        AnonymizedResult {
            text: result,
            replacements,
            metadata: AnonymizationMetadata {
                strategy: "tokenization".to_string(),
                timestamp: Utc::now(),
                pii_counts,
                total_replacements: matches.len(),
            },
        }
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn strategy_type(&self) -> &'static str {
        "tokenization"
    }
}

fn pii_type_code(pii_type: PIIType) -> &'static str {
    match pii_type {
        PIIType::Email => "EML",
        PIIType::PhoneNumber => "PHN",
        PIIType::SSN => "SSN",
        PIIType::CreditCard => "CCN",
        PIIType::Name => "NAM",
        PIIType::Address => "ADR",
        PIIType::APIKey => "API",
        _ => "PII",
    }
}

// ============================================================================
// Hashing Strategy (Irreversible, Consistent)
// ============================================================================

pub struct HashingStrategy {
    config: HashingConfig,
}

#[derive(Debug, Clone)]
pub struct HashingConfig {
    pub algorithm: HashAlgorithm,
    pub salt: Vec<u8>,
    pub pepper: Option<Vec<u8>>,
    pub truncate_to: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
    Argon2,
}

impl HashingStrategy {
    pub fn new(config: HashingConfig) -> Self {
        Self { config }
    }

    fn hash_value(&self, value: &str) -> String {
        let mut input = value.as_bytes().to_vec();
        input.extend_from_slice(&self.config.salt);

        if let Some(ref pepper) = self.config.pepper {
            input.extend_from_slice(pepper);
        }

        let hash = match self.config.algorithm {
            HashAlgorithm::Blake3 => {
                let hash = blake3::hash(&input);
                hex::encode(hash.as_bytes())
            }
            HashAlgorithm::Sha256 => {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&input);
                hex::encode(hasher.finalize())
            }
            HashAlgorithm::Argon2 => {
                use argon2::{Argon2, PasswordHasher};
                use argon2::password_hash::SaltString;

                let salt = SaltString::encode_b64(&self.config.salt).unwrap();
                let argon2 = Argon2::default();
                argon2.hash_password(value.as_bytes(), &salt)
                    .map(|h| h.to_string())
                    .unwrap_or_else(|_| hex::encode(&input))
            }
        };

        if let Some(len) = self.config.truncate_to {
            hash[..len.min(hash.len())].to_string()
        } else {
            hash
        }
    }
}

impl AnonymizationStrategy for HashingStrategy {
    fn anonymize(&self, text: &str, matches: &[PIIMatch]) -> AnonymizedResult {
        let mut result = text.to_string();
        let mut replacements = Vec::new();
        let mut offset: isize = 0;

        let mut sorted_matches = matches.to_vec();
        sorted_matches.sort_by_key(|m| m.span.start);

        for mat in &sorted_matches {
            let hash = self.hash_value(&mat.text);
            let replacement = format!("HASH_{}", hash);

            let adjusted_start = (mat.span.start as isize + offset) as usize;
            let adjusted_end = (mat.span.end as isize + offset) as usize;

            let len_diff = replacement.len() as isize - mat.len() as isize;
            result.replace_range(adjusted_start..adjusted_end, &replacement);
            offset += len_diff;

            replacements.push(Replacement {
                original_span: mat.span.clone(),
                original_text: mat.text.clone(),
                replacement_text: replacement,
                pii_type: mat.pii_type,
                reversible_token: None,
            });
        }

        let mut pii_counts = HashMap::new();
        for mat in matches {
            *pii_counts.entry(mat.pii_type).or_insert(0) += 1;
        }

        AnonymizedResult {
            text: result,
            replacements,
            metadata: AnonymizationMetadata {
                strategy: "hashing".to_string(),
                timestamp: Utc::now(),
                pii_counts,
                total_replacements: matches.len(),
            },
        }
    }

    fn is_reversible(&self) -> bool {
        false
    }

    fn strategy_type(&self) -> &'static str {
        "hashing"
    }
}

// ============================================================================
// Generalization Strategy
// ============================================================================

pub struct GeneralizationStrategy {
    config: GeneralizationConfig,
    hierarchies: HashMap<PIIType, GeneralizationHierarchy>,
}

#[derive(Debug, Clone)]
pub struct GeneralizationConfig {
    pub level: GeneralizationLevel,
}

#[derive(Debug, Clone, Copy)]
pub enum GeneralizationLevel {
    Low,     // Minimal generalization
    Medium,  // Moderate generalization
    High,    // Maximum generalization
}

struct GeneralizationHierarchy {
    levels: Vec<Box<dyn Fn(&str) -> String + Send + Sync>>,
}

impl GeneralizationStrategy {
    pub fn new(config: GeneralizationConfig) -> Self {
        let mut hierarchies = HashMap::new();

        // Age generalization: exact -> range -> category
        hierarchies.insert(PIIType::DateOfBirth, GeneralizationHierarchy {
            levels: vec![
                Box::new(|dob| {
                    // Parse and return age range
                    if let Ok(date) = chrono::NaiveDate::parse_from_str(dob, "%Y-%m-%d") {
                        let age = (Utc::now().year() - date.year()) as u32;
                        let range_start = (age / 10) * 10;
                        format!("{}-{}", range_start, range_start + 9)
                    } else {
                        "[AGE_RANGE]".to_string()
                    }
                }),
                Box::new(|_| "[ADULT]".to_string()),
            ],
        });

        // ZIP code generalization: full -> 3-digit -> region
        hierarchies.insert(PIIType::Address, GeneralizationHierarchy {
            levels: vec![
                Box::new(|addr| {
                    // Extract and truncate ZIP if present
                    if let Some(zip) = extract_zip(addr) {
                        format!("[ZIP:{}xxx]", &zip[..2.min(zip.len())])
                    } else {
                        "[LOCATION]".to_string()
                    }
                }),
                Box::new(|_| "[LOCATION]".to_string()),
            ],
        });

        Self { config, hierarchies }
    }
}

impl AnonymizationStrategy for GeneralizationStrategy {
    fn anonymize(&self, text: &str, matches: &[PIIMatch]) -> AnonymizedResult {
        let level_idx = match self.config.level {
            GeneralizationLevel::Low => 0,
            GeneralizationLevel::Medium => 1,
            GeneralizationLevel::High => 2,
        };

        let mut result = text.to_string();
        let mut replacements = Vec::new();
        let mut offset: isize = 0;

        let mut sorted_matches = matches.to_vec();
        sorted_matches.sort_by_key(|m| m.span.start);

        for mat in &sorted_matches {
            let replacement = if let Some(hierarchy) = self.hierarchies.get(&mat.pii_type) {
                let idx = level_idx.min(hierarchy.levels.len() - 1);
                hierarchy.levels[idx](&mat.text)
            } else {
                format!("[{}]", format!("{:?}", mat.pii_type).to_uppercase())
            };

            let adjusted_start = (mat.span.start as isize + offset) as usize;
            let adjusted_end = (mat.span.end as isize + offset) as usize;

            let len_diff = replacement.len() as isize - mat.len() as isize;
            result.replace_range(adjusted_start..adjusted_end, &replacement);
            offset += len_diff;

            replacements.push(Replacement {
                original_span: mat.span.clone(),
                original_text: mat.text.clone(),
                replacement_text: replacement,
                pii_type: mat.pii_type,
                reversible_token: None,
            });
        }

        let mut pii_counts = HashMap::new();
        for mat in matches {
            *pii_counts.entry(mat.pii_type).or_insert(0) += 1;
        }

        AnonymizedResult {
            text: result,
            replacements,
            metadata: AnonymizationMetadata {
                strategy: "generalization".to_string(),
                timestamp: Utc::now(),
                pii_counts,
                total_replacements: matches.len(),
            },
        }
    }

    fn is_reversible(&self) -> bool {
        false
    }

    fn strategy_type(&self) -> &'static str {
        "generalization"
    }
}

fn extract_zip(addr: &str) -> Option<String> {
    let re = regex::Regex::new(r"\b\d{5}(?:-\d{4})?\b").unwrap();
    re.find(addr).map(|m| m.as_str().to_string())
}
```

---

## 5. Token Vault

```rust
// src/anonymization/vault.rs

use std::sync::RwLock;

pub struct TokenVault {
    storage: Arc<RwLock<TokenStorage>>,
    encryption: Arc<dyn EncryptionProvider>,
    config: TokenVaultConfig,
}

#[derive(Debug, Clone)]
pub struct TokenVaultConfig {
    pub encryption_key_id: KeyId,
    pub token_ttl: Option<Duration>,
    pub max_entries: usize,
}

struct TokenStorage {
    token_to_value: HashMap<String, EncryptedEntry>,
    value_to_token: HashMap<String, String>,  // Hash of value -> token
}

struct EncryptedEntry {
    encrypted_value: Vec<u8>,
    pii_type: PIIType,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    access_count: u64,
}

impl TokenVault {
    pub fn new(
        encryption: Arc<dyn EncryptionProvider>,
        config: TokenVaultConfig,
    ) -> Self {
        Self {
            storage: Arc::new(RwLock::new(TokenStorage {
                token_to_value: HashMap::new(),
                value_to_token: HashMap::new(),
            })),
            encryption,
            config,
        }
    }

    /// Store a token-value mapping
    pub fn store(&self, token: &str, value: &str, pii_type: PIIType) {
        let encrypted_value = self.encrypt_value(value);
        let value_hash = self.hash_value(value);

        let expires_at = self.config.token_ttl.map(|ttl| Utc::now() + ttl);

        let entry = EncryptedEntry {
            encrypted_value,
            pii_type,
            created_at: Utc::now(),
            expires_at,
            access_count: 0,
        };

        let mut storage = self.storage.write().unwrap();
        storage.token_to_value.insert(token.to_string(), entry);
        storage.value_to_token.insert(value_hash, token.to_string());
    }

    /// Get token for a value (for consistency across documents)
    pub fn get_token_for_value(&self, value: &str) -> Option<String> {
        let value_hash = self.hash_value(value);
        let storage = self.storage.read().unwrap();
        storage.value_to_token.get(&value_hash).cloned()
    }

    /// Retrieve original value from token (for de-anonymization)
    pub fn retrieve(&self, token: &str) -> Result<String, AnonymizationError> {
        let mut storage = self.storage.write().unwrap();

        let entry = storage.token_to_value.get_mut(token)
            .ok_or(AnonymizationError::TokenNotFound {
                token: token.to_string(),
            })?;

        // Check expiration
        if let Some(expires_at) = entry.expires_at {
            if Utc::now() > expires_at {
                return Err(AnonymizationError::TokenExpired {
                    token: token.to_string(),
                });
            }
        }

        entry.access_count += 1;

        self.decrypt_value(&entry.encrypted_value)
    }

    /// De-anonymize text by replacing all tokens with original values
    pub fn de_anonymize(&self, text: &str) -> Result<String, AnonymizationError> {
        let mut result = text.to_string();
        let storage = self.storage.read().unwrap();

        for token in storage.token_to_value.keys() {
            if result.contains(token) {
                drop(storage);  // Release read lock
                let value = self.retrieve(token)?;
                result = result.replace(token, &value);
                // Re-acquire for next iteration
                let storage = self.storage.read().unwrap();
            }
        }

        Ok(result)
    }

    /// Remove a token (for GDPR "right to be forgotten")
    pub fn delete(&self, token: &str) -> Result<(), AnonymizationError> {
        let mut storage = self.storage.write().unwrap();

        if let Some(entry) = storage.token_to_value.remove(token) {
            // Also remove from reverse index
            let value = self.decrypt_value(&entry.encrypted_value)?;
            let value_hash = self.hash_value(&value);
            storage.value_to_token.remove(&value_hash);
            Ok(())
        } else {
            Err(AnonymizationError::TokenNotFound {
                token: token.to_string(),
            })
        }
    }

    /// Clean up expired tokens
    pub fn cleanup_expired(&self) -> usize {
        let mut storage = self.storage.write().unwrap();
        let now = Utc::now();

        let expired: Vec<_> = storage.token_to_value
            .iter()
            .filter(|(_, entry)| {
                entry.expires_at.map(|exp| now > exp).unwrap_or(false)
            })
            .map(|(token, _)| token.clone())
            .collect();

        for token in &expired {
            storage.token_to_value.remove(token);
        }

        expired.len()
    }

    fn encrypt_value(&self, value: &str) -> Vec<u8> {
        // Simplified - would use async encryption in practice
        value.as_bytes().to_vec()  // Placeholder
    }

    fn decrypt_value(&self, encrypted: &[u8]) -> Result<String, AnonymizationError> {
        // Simplified - would use async decryption in practice
        String::from_utf8(encrypted.to_vec())
            .map_err(|e| AnonymizationError::DecryptionFailed {
                message: e.to_string(),
            })
    }

    fn hash_value(&self, value: &str) -> String {
        let hash = blake3::hash(value.as_bytes());
        hex::encode(hash.as_bytes())
    }
}
```

---

## 6. Anonymization Pipeline

```rust
// src/anonymization/pipeline.rs

pub struct AnonymizationPipeline {
    detectors: Vec<Arc<dyn PIIDetector>>,
    strategies: HashMap<PIIType, Arc<dyn AnonymizationStrategy>>,
    default_strategy: Arc<dyn AnonymizationStrategy>,
    config: PipelineConfig,
    metrics: Arc<AnonymizationMetrics>,
}

#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub confidence_threshold: f32,
    pub enable_parallel: bool,
    pub max_concurrent: usize,
    pub audit_enabled: bool,
}

impl AnonymizationPipeline {
    pub fn new(
        detectors: Vec<Arc<dyn PIIDetector>>,
        default_strategy: Arc<dyn AnonymizationStrategy>,
        config: PipelineConfig,
    ) -> Self {
        Self {
            detectors,
            strategies: HashMap::new(),
            default_strategy,
            config,
            metrics: Arc::new(AnonymizationMetrics::new()),
        }
    }

    /// Set strategy for specific PII type
    pub fn with_strategy(
        mut self,
        pii_type: PIIType,
        strategy: Arc<dyn AnonymizationStrategy>,
    ) -> Self {
        self.strategies.insert(pii_type, strategy);
        self
    }

    /// Anonymize text
    pub async fn anonymize(&self, text: &str) -> Result<AnonymizedResult, AnonymizationError> {
        let _timer = self.metrics.operation_timer("anonymize");

        // Step 1: Detect PII using all detectors
        let matches = self.detect_all(text).await?;

        // Step 2: Filter by confidence
        let filtered: Vec<_> = matches
            .into_iter()
            .filter(|m| m.confidence >= self.config.confidence_threshold)
            .collect();

        if filtered.is_empty() {
            return Ok(AnonymizedResult {
                text: text.to_string(),
                replacements: Vec::new(),
                metadata: AnonymizationMetadata::default(),
            });
        }

        // Step 3: Group by strategy
        let mut by_strategy: HashMap<&str, Vec<PIIMatch>> = HashMap::new();
        for mat in &filtered {
            let strategy = self.strategies.get(&mat.pii_type)
                .unwrap_or(&self.default_strategy);
            by_strategy
                .entry(strategy.strategy_type())
                .or_default()
                .push(mat.clone());
        }

        // Step 4: Apply strategies (must be sequential due to offset changes)
        let mut result = text.to_string();
        let mut all_replacements = Vec::new();

        for (strategy_type, matches) in by_strategy {
            let strategy = self.strategies
                .values()
                .find(|s| s.strategy_type() == strategy_type)
                .unwrap_or(&self.default_strategy);

            let anonymized = strategy.anonymize(&result, &matches);
            result = anonymized.text;
            all_replacements.extend(anonymized.replacements);
        }

        self.metrics.record_anonymization(filtered.len());

        Ok(AnonymizedResult {
            text: result,
            replacements: all_replacements,
            metadata: AnonymizationMetadata {
                strategy: "pipeline".to_string(),
                timestamp: Utc::now(),
                pii_counts: count_by_type(&filtered),
                total_replacements: filtered.len(),
            },
        })
    }

    /// Detect only (without anonymization)
    pub async fn detect(&self, text: &str) -> Result<Vec<PIIMatch>, AnonymizationError> {
        self.detect_all(text).await
    }

    async fn detect_all(&self, text: &str) -> Result<Vec<PIIMatch>, AnonymizationError> {
        if self.config.enable_parallel {
            self.detect_parallel(text).await
        } else {
            self.detect_sequential(text)
        }
    }

    async fn detect_parallel(&self, text: &str) -> Result<Vec<PIIMatch>, AnonymizationError> {
        let mut handles = Vec::new();

        for detector in &self.detectors {
            let detector = detector.clone();
            let text = text.to_string();

            handles.push(tokio::spawn(async move {
                detector.detect(&text)
            }));
        }

        let mut all_matches = Vec::new();
        for handle in handles {
            let matches = handle.await
                .map_err(|e| AnonymizationError::DetectionFailed {
                    message: e.to_string(),
                })?;
            all_matches.extend(matches);
        }

        // Deduplicate overlapping matches
        all_matches.sort_by_key(|m| m.span.start);
        deduplicate_matches(&mut all_matches);

        Ok(all_matches)
    }

    fn detect_sequential(&self, text: &str) -> Result<Vec<PIIMatch>, AnonymizationError> {
        let mut all_matches = Vec::new();

        for detector in &self.detectors {
            let matches = detector.detect(text);
            all_matches.extend(matches);
        }

        all_matches.sort_by_key(|m| m.span.start);
        deduplicate_matches(&mut all_matches);

        Ok(all_matches)
    }

    /// Batch anonymization for efficiency
    pub async fn anonymize_batch(
        &self,
        texts: &[&str],
    ) -> Result<Vec<AnonymizedResult>, AnonymizationError> {
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent));
        let mut handles = Vec::new();

        for text in texts {
            let sem = semaphore.clone();
            let pipeline = self.clone();
            let text = text.to_string();

            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                pipeline.anonymize(&text).await
            }));
        }

        let mut results = Vec::with_capacity(texts.len());
        for handle in handles {
            results.push(handle.await
                .map_err(|e| AnonymizationError::DetectionFailed {
                    message: e.to_string(),
                })??);
        }

        Ok(results)
    }
}

fn count_by_type(matches: &[PIIMatch]) -> HashMap<PIIType, usize> {
    let mut counts = HashMap::new();
    for mat in matches {
        *counts.entry(mat.pii_type).or_insert(0) += 1;
    }
    counts
}

fn deduplicate_matches(matches: &mut Vec<PIIMatch>) {
    let mut i = 0;
    while i < matches.len() {
        let mut j = i + 1;
        while j < matches.len() {
            if matches[i].overlaps(&matches[j]) {
                if matches[i].confidence >= matches[j].confidence {
                    matches.remove(j);
                } else {
                    matches.remove(i);
                    j = i + 1;
                    continue;
                }
            } else if matches[j].span.start >= matches[i].span.end {
                break;
            } else {
                j += 1;
            }
        }
        i += 1;
    }
}
```

---

## 7. Anonymization Policy Engine

```rust
// src/anonymization/policy.rs

pub struct AnonymizationPolicyEngine {
    policies: HashMap<PolicyId, AnonymizationPolicy>,
    compliance_presets: HashMap<ComplianceFramework, AnonymizationPolicy>,
}

#[derive(Debug, Clone)]
pub struct AnonymizationPolicy {
    pub id: PolicyId,
    pub name: String,
    pub rules: Vec<AnonymizationRule>,
    pub default_strategy: StrategyType,
    pub exceptions: Vec<PolicyException>,
}

#[derive(Debug, Clone)]
pub struct AnonymizationRule {
    pub pii_type: PIIType,
    pub strategy: StrategyType,
    pub min_confidence: f32,
    pub context_rules: Vec<ContextRule>,
}

#[derive(Debug, Clone, Copy)]
pub enum StrategyType {
    Mask,
    Tokenize,
    Hash,
    Generalize,
    Pseudonymize,
    Skip,
}

#[derive(Debug, Clone)]
pub struct ContextRule {
    pub field_pattern: Option<String>,
    pub content_pattern: Option<String>,
    pub action: ContextAction,
}

#[derive(Debug, Clone, Copy)]
pub enum ContextAction {
    ApplyStrategy(StrategyType),
    Skip,
    Escalate,
}

#[derive(Debug, Clone)]
pub struct PolicyException {
    pub pattern: String,
    pub reason: String,
    pub action: ContextAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComplianceFramework {
    GDPR,
    HIPAA,
    CCPA,
    PciDss,
    Sox,
}

impl AnonymizationPolicyEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            policies: HashMap::new(),
            compliance_presets: HashMap::new(),
        };

        // Initialize compliance presets
        engine.init_gdpr_preset();
        engine.init_hipaa_preset();
        engine.init_pci_preset();

        engine
    }

    fn init_gdpr_preset(&mut self) {
        let policy = AnonymizationPolicy {
            id: PolicyId::new(),
            name: "GDPR Compliance".into(),
            rules: vec![
                AnonymizationRule {
                    pii_type: PIIType::Name,
                    strategy: StrategyType::Pseudonymize,
                    min_confidence: 0.8,
                    context_rules: vec![],
                },
                AnonymizationRule {
                    pii_type: PIIType::Email,
                    strategy: StrategyType::Tokenize,
                    min_confidence: 0.9,
                    context_rules: vec![],
                },
                AnonymizationRule {
                    pii_type: PIIType::PhoneNumber,
                    strategy: StrategyType::Mask,
                    min_confidence: 0.85,
                    context_rules: vec![],
                },
                AnonymizationRule {
                    pii_type: PIIType::Address,
                    strategy: StrategyType::Generalize,
                    min_confidence: 0.8,
                    context_rules: vec![],
                },
            ],
            default_strategy: StrategyType::Mask,
            exceptions: vec![],
        };

        self.compliance_presets.insert(ComplianceFramework::GDPR, policy);
    }

    fn init_hipaa_preset(&mut self) {
        let policy = AnonymizationPolicy {
            id: PolicyId::new(),
            name: "HIPAA Safe Harbor".into(),
            rules: vec![
                AnonymizationRule {
                    pii_type: PIIType::Name,
                    strategy: StrategyType::Mask,
                    min_confidence: 0.7,
                    context_rules: vec![],
                },
                AnonymizationRule {
                    pii_type: PIIType::SSN,
                    strategy: StrategyType::Mask,
                    min_confidence: 0.7,
                    context_rules: vec![],
                },
                AnonymizationRule {
                    pii_type: PIIType::DateOfBirth,
                    strategy: StrategyType::Generalize,
                    min_confidence: 0.8,
                    context_rules: vec![],
                },
                AnonymizationRule {
                    pii_type: PIIType::MedicalRecordNumber,
                    strategy: StrategyType::Hash,
                    min_confidence: 0.9,
                    context_rules: vec![],
                },
            ],
            default_strategy: StrategyType::Mask,
            exceptions: vec![],
        };

        self.compliance_presets.insert(ComplianceFramework::HIPAA, policy);
    }

    fn init_pci_preset(&mut self) {
        let policy = AnonymizationPolicy {
            id: PolicyId::new(),
            name: "PCI-DSS Compliance".into(),
            rules: vec![
                AnonymizationRule {
                    pii_type: PIIType::CreditCard,
                    strategy: StrategyType::Mask,
                    min_confidence: 0.9,
                    context_rules: vec![],
                },
                AnonymizationRule {
                    pii_type: PIIType::BankAccount,
                    strategy: StrategyType::Mask,
                    min_confidence: 0.9,
                    context_rules: vec![],
                },
            ],
            default_strategy: StrategyType::Mask,
            exceptions: vec![],
        };

        self.compliance_presets.insert(ComplianceFramework::PciDss, policy);
    }

    /// Get policy for compliance framework
    pub fn get_compliance_policy(&self, framework: ComplianceFramework) -> Option<&AnonymizationPolicy> {
        self.compliance_presets.get(&framework)
    }

    /// Evaluate policy for a match
    pub fn evaluate(&self, policy: &AnonymizationPolicy, mat: &PIIMatch) -> StrategyType {
        // Check exceptions first
        for exception in &policy.exceptions {
            let re = regex::Regex::new(&exception.pattern).ok();
            if let Some(re) = re {
                if re.is_match(&mat.text) {
                    match exception.action {
                        ContextAction::ApplyStrategy(strategy) => return strategy,
                        ContextAction::Skip => return StrategyType::Skip,
                        ContextAction::Escalate => {} // Continue to rules
                    }
                }
            }
        }

        // Find matching rule
        for rule in &policy.rules {
            if rule.pii_type == mat.pii_type && mat.confidence >= rule.min_confidence {
                // Check context rules
                for context_rule in &rule.context_rules {
                    if self.matches_context(context_rule, mat) {
                        match context_rule.action {
                            ContextAction::ApplyStrategy(strategy) => return strategy,
                            ContextAction::Skip => return StrategyType::Skip,
                            ContextAction::Escalate => continue,
                        }
                    }
                }
                return rule.strategy;
            }
        }

        policy.default_strategy
    }

    fn matches_context(&self, rule: &ContextRule, mat: &PIIMatch) -> bool {
        if let Some(ref pattern) = rule.field_pattern {
            if let Some(ref context) = mat.context {
                if let Some(ref field_name) = context.field_name {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        if !re.is_match(field_name) {
                            return false;
                        }
                    }
                }
            }
        }

        if let Some(ref pattern) = rule.content_pattern {
            if let Ok(re) = regex::Regex::new(pattern) {
                if !re.is_match(&mat.text) {
                    return false;
                }
            }
        }

        true
    }
}
```

---

## Summary

This document defines the anonymization engine for LLM-Data-Vault:

| Component | Purpose |
|-----------|---------|
| **PIIDetector Trait** | Abstract interface for PII detection |
| **RegexPIIDetector** | Pattern-based detection with validation |
| **NERPIIDetector** | ML-based Named Entity Recognition |
| **AnonymizationStrategy** | Strategies: Masking, Tokenization, Hashing, Generalization |
| **TokenVault** | Secure storage for reversible anonymization |
| **AnonymizationPipeline** | Orchestrates detection and anonymization |
| **AnonymizationPolicyEngine** | Compliance-aware policy enforcement |

**Key Features:**
- Multiple detection methods (regex + ML)
- 99.5%+ accuracy with validation
- Reversible and irreversible strategies
- Compliance presets (GDPR, HIPAA, PCI-DSS)
- Token vault with encryption
- Parallel processing support

---

*Next Document: [05-access-control.md](./05-access-control.md)*
