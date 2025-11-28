//! Main anonymization engine.

use crate::{
    AnonymizeError, AnonymizeResult, AnonymizationStrategy, Detection, DetectorConfig,
    PIIRiskLevel, PiiDetector, StrategyConfig, StrategyExecutor,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vault_core::record::{PIIAnnotation, PIIType};

/// Anonymizer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizerConfig {
    /// Detector configuration.
    pub detector: DetectorConfig,
    /// Strategy configuration.
    pub strategy: StrategyConfig,
    /// Enable audit logging.
    pub audit_logging: bool,
    /// Preserve original in metadata.
    pub preserve_original: bool,
    /// Process nested JSON.
    pub process_nested: bool,
}

impl Default for AnonymizerConfig {
    fn default() -> Self {
        Self {
            detector: DetectorConfig::default(),
            strategy: StrategyConfig::default(),
            audit_logging: true,
            preserve_original: false,
            process_nested: true,
        }
    }
}

impl AnonymizerConfig {
    /// Creates a HIPAA-compliant configuration.
    #[must_use]
    pub fn hipaa() -> Self {
        let mut strategy = StrategyConfig::default();
        strategy.default_strategy = AnonymizationStrategy::Redact;
        strategy.type_strategies.insert(PIIType::Name, AnonymizationStrategy::Substitute);
        strategy.type_strategies.insert(PIIType::DateOfBirth, AnonymizationStrategy::Generalize);
        strategy.type_strategies.insert(PIIType::Ssn, AnonymizationStrategy::Redact);
        strategy.type_strategies.insert(PIIType::MedicalRecord, AnonymizationStrategy::Tokenize);
        strategy.type_strategies.insert(PIIType::HealthInfo, AnonymizationStrategy::Redact);

        Self {
            detector: DetectorConfig::permissive(),
            strategy,
            audit_logging: true,
            preserve_original: false,
            process_nested: true,
        }
    }

    /// Creates a GDPR-compliant configuration.
    #[must_use]
    pub fn gdpr() -> Self {
        let mut strategy = StrategyConfig::default();
        strategy.default_strategy = AnonymizationStrategy::Mask;
        strategy.deterministic_tokens = true;

        Self {
            detector: DetectorConfig::default(),
            strategy,
            audit_logging: true,
            preserve_original: false,
            process_nested: true,
        }
    }

    /// Creates a PCI-DSS compliant configuration.
    #[must_use]
    pub fn pci_dss() -> Self {
        let mut strategy = StrategyConfig::default();
        strategy.type_strategies.insert(PIIType::CreditCard, AnonymizationStrategy::Mask);
        strategy.type_strategies.insert(PIIType::BankAccount, AnonymizationStrategy::Redact);
        strategy.preserve_format = true;

        Self {
            detector: DetectorConfig {
                min_risk_level: PIIRiskLevel::High,
                ..Default::default()
            },
            strategy,
            audit_logging: true,
            preserve_original: false,
            process_nested: true,
        }
    }
}

/// Anonymized output.
#[derive(Debug, Clone)]
pub struct AnonymizedOutput {
    /// Anonymized text.
    pub text: String,
    /// Original text (if preserved).
    pub original: Option<String>,
    /// Detections that were anonymized.
    pub detections: Vec<Detection>,
    /// Annotations with anonymization info.
    pub annotations: Vec<PIIAnnotation>,
    /// Statistics.
    pub stats: AnonymizationStats,
    /// Token mappings (for reversible anonymization).
    pub token_map: HashMap<String, String>,
}

/// Anonymization statistics.
#[derive(Debug, Clone, Default)]
pub struct AnonymizationStats {
    /// Total PII instances found.
    pub total_pii_found: usize,
    /// Total PII instances anonymized.
    pub total_anonymized: usize,
    /// Anonymizations by type.
    pub by_type: HashMap<PIIType, usize>,
    /// Anonymizations by strategy.
    pub by_strategy: HashMap<AnonymizationStrategy, usize>,
    /// Processing time in milliseconds.
    pub processing_time_ms: u64,
}

/// Main anonymizer.
pub struct Anonymizer {
    detector: PiiDetector,
    executor: StrategyExecutor,
    config: AnonymizerConfig,
}

impl Anonymizer {
    /// Creates a new anonymizer.
    #[must_use]
    pub fn new(config: AnonymizerConfig) -> Self {
        Self {
            detector: PiiDetector::with_config(config.detector.clone()),
            executor: StrategyExecutor::new(config.strategy.clone()),
            config,
        }
    }

    /// Creates with default configuration.
    #[must_use]
    pub fn default_anonymizer() -> Self {
        Self::new(AnonymizerConfig::default())
    }

    /// Anonymizes text.
    pub fn anonymize(&self, text: &str) -> AnonymizeResult<AnonymizedOutput> {
        let start = std::time::Instant::now();

        // Detect PII
        let detections = self.detector.detect(text);

        // Anonymize detections
        let (anonymized_text, annotations) = self.apply_anonymizations(text, &detections)?;

        // Gather statistics
        let mut stats = AnonymizationStats {
            total_pii_found: detections.len(),
            total_anonymized: annotations.len(),
            processing_time_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        };

        for d in &detections {
            *stats.by_type.entry(d.pii_type.clone()).or_insert(0) += 1;
            let strategy = self.config.strategy.strategy_for(&d.pii_type);
            *stats.by_strategy.entry(strategy).or_insert(0) += 1;
        }

        Ok(AnonymizedOutput {
            text: anonymized_text,
            original: if self.config.preserve_original {
                Some(text.to_string())
            } else {
                None
            },
            detections,
            annotations,
            stats,
            token_map: self.executor.get_token_map(),
        })
    }

    /// Anonymizes JSON value.
    pub fn anonymize_json(
        &self,
        value: &serde_json::Value,
    ) -> AnonymizeResult<(serde_json::Value, AnonymizedOutput)> {
        let start = std::time::Instant::now();

        let mut all_detections = Vec::new();
        let mut all_annotations = Vec::new();

        let anonymized = self.anonymize_json_recursive(
            value,
            &mut Vec::new(),
            &mut all_detections,
            &mut all_annotations,
        )?;

        let mut stats = AnonymizationStats {
            total_pii_found: all_detections.len(),
            total_anonymized: all_annotations.len(),
            processing_time_ms: start.elapsed().as_millis() as u64,
            ..Default::default()
        };

        for d in &all_detections {
            *stats.by_type.entry(d.pii_type.clone()).or_insert(0) += 1;
            let strategy = self.config.strategy.strategy_for(&d.pii_type);
            *stats.by_strategy.entry(strategy).or_insert(0) += 1;
        }

        let output = AnonymizedOutput {
            text: serde_json::to_string(&anonymized).unwrap_or_default(),
            original: if self.config.preserve_original {
                Some(serde_json::to_string(value).unwrap_or_default())
            } else {
                None
            },
            detections: all_detections,
            annotations: all_annotations,
            stats,
            token_map: self.executor.get_token_map(),
        };

        Ok((anonymized, output))
    }

    fn anonymize_json_recursive(
        &self,
        value: &serde_json::Value,
        path: &mut Vec<String>,
        detections: &mut Vec<Detection>,
        annotations: &mut Vec<PIIAnnotation>,
    ) -> AnonymizeResult<serde_json::Value> {
        match value {
            serde_json::Value::String(s) => {
                let text_detections = self.detector.detect(s);
                if text_detections.is_empty() {
                    return Ok(value.clone());
                }

                let (anonymized, anns) = self.apply_anonymizations(s, &text_detections)?;

                // Update detection paths - just add to collections
                detections.extend(text_detections);
                annotations.extend(anns);

                Ok(serde_json::Value::String(anonymized))
            }
            serde_json::Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (key, val) in map {
                    path.push(key.clone());
                    let new_val = self.anonymize_json_recursive(val, path, detections, annotations)?;
                    new_map.insert(key.clone(), new_val);
                    path.pop();
                }
                Ok(serde_json::Value::Object(new_map))
            }
            serde_json::Value::Array(arr) => {
                let mut new_arr = Vec::new();
                for (i, val) in arr.iter().enumerate() {
                    path.push(format!("[{}]", i));
                    let new_val = self.anonymize_json_recursive(val, path, detections, annotations)?;
                    new_arr.push(new_val);
                    path.pop();
                }
                Ok(serde_json::Value::Array(new_arr))
            }
            _ => Ok(value.clone()),
        }
    }

    /// Applies anonymizations to text based on detections.
    fn apply_anonymizations(
        &self,
        text: &str,
        detections: &[Detection],
    ) -> AnonymizeResult<(String, Vec<PIIAnnotation>)> {
        if detections.is_empty() {
            return Ok((text.to_string(), Vec::new()));
        }

        // Sort detections by position (reverse order for replacement)
        let mut sorted: Vec<&Detection> = detections.iter().collect();
        sorted.sort_by(|a, b| {
            let start_b = b.location.start().unwrap_or(0);
            let start_a = a.location.start().unwrap_or(0);
            start_b.cmp(&start_a)
        });

        let mut result = text.to_string();
        let mut annotations = Vec::new();

        for detection in sorted {
            let strategy = self.config.strategy.strategy_for(&detection.pii_type);
            let anonymized = self.executor.apply_strategy(strategy, &detection.value, &detection.pii_type)?;

            // Replace in text if we have byte range
            if let (Some(start), Some(end)) = (detection.location.start(), detection.location.end()) {
                result.replace_range(start..end, &anonymized);
            }

            // Create annotation
            annotations.push(PIIAnnotation {
                pii_type: detection.pii_type.clone(),
                location: detection.location.clone(),
                confidence: detection.confidence,
                risk_level: detection.risk_level,
                detected_value: if self.config.preserve_original {
                    Some(detection.value.clone())
                } else {
                    None
                },
                is_anonymized: true,
                anonymization_strategy: Some(format!("{:?}", strategy)),
                anonymization_method: Some(format!("{:?}", strategy)),
            });
        }

        Ok((result, annotations))
    }

    /// Re-identifies tokenized data.
    pub fn reidentify(&self, text: &str, token_map: &HashMap<String, String>) -> String {
        let mut result = text.to_string();

        // Reverse the token map (token -> original)
        let reverse_map: HashMap<&str, &str> = token_map
            .iter()
            .map(|(k, v)| (v.as_str(), k.as_str()))
            .collect();

        for (token, original) in &reverse_map {
            result = result.replace(*token, original);
        }

        result
    }

    /// Clears internal token mappings.
    pub fn clear_tokens(&self) {
        self.executor.clear_token_map();
    }

    /// Returns the current configuration.
    #[must_use]
    pub fn config(&self) -> &AnonymizerConfig {
        &self.config
    }
}

impl Default for Anonymizer {
    fn default() -> Self {
        Self::default_anonymizer()
    }
}

/// Batch anonymizer for processing multiple records.
pub struct BatchAnonymizer {
    anonymizer: Anonymizer,
}

impl BatchAnonymizer {
    /// Creates a new batch anonymizer.
    pub fn new(config: AnonymizerConfig) -> Self {
        Self {
            anonymizer: Anonymizer::new(config),
        }
    }

    /// Anonymizes multiple texts.
    pub fn anonymize_batch(&self, texts: &[&str]) -> Vec<AnonymizeResult<AnonymizedOutput>> {
        texts
            .iter()
            .map(|t| self.anonymizer.anonymize(t))
            .collect()
    }

    /// Anonymizes multiple JSON values.
    pub fn anonymize_json_batch(
        &self,
        values: &[serde_json::Value],
    ) -> Vec<AnonymizeResult<(serde_json::Value, AnonymizedOutput)>> {
        values
            .iter()
            .map(|v| self.anonymizer.anonymize_json(v))
            .collect()
    }
}

/// Streaming anonymizer for large datasets.
pub struct StreamingAnonymizer {
    anonymizer: Anonymizer,
    buffer_size: usize,
}

impl StreamingAnonymizer {
    /// Creates a new streaming anonymizer.
    pub fn new(config: AnonymizerConfig, buffer_size: usize) -> Self {
        Self {
            anonymizer: Anonymizer::new(config),
            buffer_size,
        }
    }

    /// Processes a chunk of text.
    pub fn process_chunk(&self, chunk: &str) -> AnonymizeResult<AnonymizedOutput> {
        self.anonymizer.anonymize(chunk)
    }

    /// Returns the buffer size.
    #[must_use]
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_anonymization() {
        let anonymizer = Anonymizer::default();
        let text = "Contact john@example.com for details.";

        let result = anonymizer.anonymize(text).unwrap();

        assert!(!result.text.contains("john@example.com"));
        assert!(!result.detections.is_empty());
        assert!(result.stats.total_pii_found > 0);
    }

    #[test]
    fn test_json_anonymization() {
        let anonymizer = Anonymizer::default();
        let json = serde_json::json!({
            "user": {
                "email": "test@example.com",
                "phone": "555-123-4567"
            }
        });

        let (anonymized, output) = anonymizer.anonymize_json(&json).unwrap();

        assert!(anonymized["user"]["email"].as_str().unwrap() != "test@example.com");
        assert!(!output.detections.is_empty());
    }

    #[test]
    fn test_hipaa_config() {
        let config = AnonymizerConfig::hipaa();
        let anonymizer = Anonymizer::new(config);

        let text = "Patient John Doe, SSN: 123-45-6789";
        let result = anonymizer.anonymize(text).unwrap();

        assert!(!result.text.contains("123-45-6789"));
    }

    #[test]
    fn test_tokenize_reidentify() {
        let config = AnonymizerConfig {
            strategy: StrategyConfig {
                default_strategy: AnonymizationStrategy::Tokenize,
                deterministic_tokens: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let anonymizer = Anonymizer::new(config);
        let text = "Email: secret@example.com";

        let result = anonymizer.anonymize(text).unwrap();
        assert!(!result.text.contains("secret@example.com"));

        // Re-identify
        let reidentified = anonymizer.reidentify(&result.text, &result.token_map);
        assert!(reidentified.contains("secret@example.com"));
    }

    #[test]
    fn test_statistics() {
        let anonymizer = Anonymizer::default();
        let text = "Email: a@b.com, Phone: 555-1234, SSN: 123-45-6789";

        let result = anonymizer.anonymize(text).unwrap();

        assert!(result.stats.total_pii_found >= 3);
        assert!(result.stats.by_type.len() >= 3);
        assert!(result.stats.processing_time_ms >= 0);
    }

    #[test]
    fn test_batch_anonymization() {
        let batch = BatchAnonymizer::new(AnonymizerConfig::default());
        let texts = vec!["email: a@b.com", "phone: 555-1234"];

        let results = batch.anonymize_batch(&texts);

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));
    }
}
