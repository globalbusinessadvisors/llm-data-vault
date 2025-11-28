//! PII detection engine.

use crate::{
    AnonymizeError, AnonymizeResult, PIICategory, PIIRiskLevel, PatternMatch, PatternMatcher,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vault_core::record::{PIIAnnotation, PIILocation, PIIType};

/// PII detector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    /// Minimum confidence threshold (0.0 - 1.0).
    pub min_confidence: f64,
    /// Minimum risk level to detect.
    pub min_risk_level: PIIRiskLevel,
    /// PII types to detect (empty = all).
    pub include_types: Vec<PIIType>,
    /// PII types to exclude.
    pub exclude_types: Vec<PIIType>,
    /// Enable context analysis.
    pub context_analysis: bool,
    /// Context window size (chars).
    pub context_window: usize,
    /// Enable ML-based detection (if available).
    pub use_ml: bool,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            min_confidence: 0.5,
            min_risk_level: PIIRiskLevel::Low,
            include_types: Vec::new(),
            exclude_types: Vec::new(),
            context_analysis: true,
            context_window: 100,
            use_ml: false,
        }
    }
}

impl DetectorConfig {
    /// Creates a strict config (high confidence, critical risk only).
    #[must_use]
    pub fn strict() -> Self {
        Self {
            min_confidence: 0.9,
            min_risk_level: PIIRiskLevel::High,
            ..Default::default()
        }
    }

    /// Creates a permissive config (low confidence, all risks).
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            min_confidence: 0.3,
            min_risk_level: PIIRiskLevel::Low,
            ..Default::default()
        }
    }
}

/// A PII detection result.
#[derive(Debug, Clone)]
pub struct Detection {
    /// Detected PII type.
    pub pii_type: PIIType,
    /// Location in the text.
    pub location: PIILocation,
    /// Detected value.
    pub value: String,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Risk level.
    pub risk_level: PIIRiskLevel,
    /// Detection method.
    pub method: DetectionMethod,
    /// Context around the detection.
    pub context: Option<String>,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

impl Detection {
    /// Converts to a PII annotation.
    #[must_use]
    pub fn to_annotation(&self) -> PIIAnnotation {
        PIIAnnotation {
            pii_type: self.pii_type.clone(),
            location: self.location.clone(),
            confidence: self.confidence,
            risk_level: self.risk_level,
            detected_value: Some(self.value.clone()),
            is_anonymized: false,
            anonymization_strategy: None,
            anonymization_method: None,
        }
    }
}

/// Detection method used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DetectionMethod {
    /// Pattern matching (regex).
    Pattern,
    /// Contextual analysis.
    Contextual,
    /// Machine learning model.
    MachineLearning,
    /// Custom detector.
    Custom,
}

/// PII detector.
pub struct PiiDetector {
    matcher: PatternMatcher,
    config: DetectorConfig,
    custom_detectors: Vec<Box<dyn CustomDetector>>,
}

/// Custom detector trait.
pub trait CustomDetector: Send + Sync {
    /// Returns the detector name.
    fn name(&self) -> &str;

    /// Detects PII in text.
    fn detect(&self, text: &str) -> Vec<Detection>;

    /// Returns supported PII types.
    fn supported_types(&self) -> Vec<PIIType>;
}

impl PiiDetector {
    /// Creates a new detector with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            matcher: PatternMatcher::new(),
            config: DetectorConfig::default(),
            custom_detectors: Vec::new(),
        }
    }

    /// Creates with custom config.
    #[must_use]
    pub fn with_config(config: DetectorConfig) -> Self {
        Self {
            matcher: PatternMatcher::new(),
            config,
            custom_detectors: Vec::new(),
        }
    }

    /// Adds a custom detector.
    pub fn add_custom_detector(&mut self, detector: Box<dyn CustomDetector>) {
        self.custom_detectors.push(detector);
    }

    /// Detects all PII in text.
    pub fn detect(&self, text: &str) -> Vec<Detection> {
        let mut detections = Vec::new();

        // Pattern-based detection
        let pattern_matches = self.matcher.find_validated(text);
        for m in pattern_matches {
            if self.should_include(&m) {
                let context = if self.config.context_analysis {
                    Some(self.extract_context(text, m.start, m.end))
                } else {
                    None
                };

                detections.push(Detection {
                    pii_type: m.pii_type,
                    location: PIILocation::ByteRange {
                        start: m.start,
                        end: m.end,
                    },
                    value: m.matched_text,
                    confidence: m.confidence,
                    risk_level: m.risk_level,
                    method: DetectionMethod::Pattern,
                    context,
                    metadata: HashMap::new(),
                });
            }
        }

        // Custom detectors
        for detector in &self.custom_detectors {
            let custom_detections = detector.detect(text);
            for d in custom_detections {
                if self.should_include_detection(&d) {
                    detections.push(d);
                }
            }
        }

        // Remove duplicates and overlapping detections
        self.deduplicate(&mut detections);

        detections
    }

    /// Detects PII in structured data (JSON).
    pub fn detect_json(&self, value: &serde_json::Value) -> Vec<Detection> {
        let mut detections = Vec::new();
        self.detect_json_recursive(value, &mut Vec::new(), &mut detections);
        detections
    }

    fn detect_json_recursive(
        &self,
        value: &serde_json::Value,
        path: &mut Vec<String>,
        detections: &mut Vec<Detection>,
    ) {
        match value {
            serde_json::Value::String(s) => {
                let path_str = path.join(".");
                let text_detections = self.detect(s);

                // Convert to JSON path locations
                for d in text_detections {
                    let mut new_detection = d;
                    new_detection.location = PIILocation::JsonPath { path: path_str.clone() };
                    detections.push(new_detection);
                }
            }
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    path.push(key.clone());
                    self.detect_json_recursive(val, path, detections);
                    path.pop();
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    path.push(format!("[{}]", i));
                    self.detect_json_recursive(val, path, detections);
                    path.pop();
                }
            }
            _ => {}
        }
    }

    /// Checks if a detection should be included based on config.
    fn should_include(&self, m: &PatternMatch) -> bool {
        // Check confidence
        if m.confidence < self.config.min_confidence {
            return false;
        }

        // Check risk level
        if (m.risk_level as u8) < (self.config.min_risk_level as u8) {
            return false;
        }

        // Check include list
        if !self.config.include_types.is_empty()
            && !self.config.include_types.contains(&m.pii_type)
        {
            return false;
        }

        // Check exclude list
        if self.config.exclude_types.contains(&m.pii_type) {
            return false;
        }

        true
    }

    fn should_include_detection(&self, d: &Detection) -> bool {
        if d.confidence < self.config.min_confidence {
            return false;
        }

        if (d.risk_level as u8) < (self.config.min_risk_level as u8) {
            return false;
        }

        if !self.config.include_types.is_empty()
            && !self.config.include_types.contains(&d.pii_type)
        {
            return false;
        }

        if self.config.exclude_types.contains(&d.pii_type) {
            return false;
        }

        true
    }

    /// Extracts context around a detection.
    fn extract_context(&self, text: &str, start: usize, end: usize) -> String {
        let window = self.config.context_window;
        let ctx_start = start.saturating_sub(window);
        let ctx_end = (end + window).min(text.len());

        let mut context = String::new();
        if ctx_start > 0 {
            context.push_str("...");
        }
        context.push_str(&text[ctx_start..ctx_end]);
        if ctx_end < text.len() {
            context.push_str("...");
        }

        context
    }

    /// Removes duplicate and overlapping detections.
    fn deduplicate(&self, detections: &mut Vec<Detection>) {
        // Sort by position, then by confidence (desc)
        detections.sort_by(|a, b| {
            let start_a = a.location.start().unwrap_or(0);
            let start_b = b.location.start().unwrap_or(0);
            start_a
                .cmp(&start_b)
                .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap())
        });

        // Remove overlapping (keep highest confidence)
        let mut i = 0;
        while i < detections.len() {
            let mut j = i + 1;
            while j < detections.len() {
                let start_j = detections[j].location.start().unwrap_or(0);
                let end_i = detections[i].location.end().unwrap_or(0);
                if start_j < end_i {
                    // Overlapping - remove the one with lower confidence
                    if detections[j].confidence > detections[i].confidence {
                        detections.remove(i);
                        continue;
                    } else {
                        detections.remove(j);
                        continue;
                    }
                }
                j += 1;
            }
            i += 1;
        }
    }

    /// Returns detection statistics.
    pub fn stats(&self, detections: &[Detection]) -> DetectionStats {
        let mut stats = DetectionStats::default();

        for d in detections {
            stats.total += 1;
            *stats.by_type.entry(d.pii_type.clone()).or_insert(0) += 1;
            *stats.by_risk.entry(d.risk_level).or_insert(0) += 1;
            *stats.by_method.entry(d.method).or_insert(0) += 1;

            let category = PIICategory::from_pii_type(&d.pii_type);
            *stats.by_category.entry(category).or_insert(0) += 1;

            stats.avg_confidence =
                (stats.avg_confidence * (stats.total - 1) as f64 + d.confidence) / stats.total as f64;
        }

        stats
    }
}

impl Default for PiiDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Detection statistics.
#[derive(Debug, Clone, Default)]
pub struct DetectionStats {
    /// Total detections.
    pub total: usize,
    /// Detections by PII type.
    pub by_type: HashMap<PIIType, usize>,
    /// Detections by risk level.
    pub by_risk: HashMap<PIIRiskLevel, usize>,
    /// Detections by category.
    pub by_category: HashMap<PIICategory, usize>,
    /// Detections by method.
    pub by_method: HashMap<DetectionMethod, usize>,
    /// Average confidence.
    pub avg_confidence: f64,
}

/// Batch detector for processing multiple texts.
pub struct BatchDetector {
    detector: PiiDetector,
    batch_size: usize,
}

impl BatchDetector {
    /// Creates a new batch detector.
    pub fn new(config: DetectorConfig, batch_size: usize) -> Self {
        Self {
            detector: PiiDetector::with_config(config),
            batch_size,
        }
    }

    /// Detects PII in multiple texts.
    pub fn detect_batch(&self, texts: &[&str]) -> Vec<Vec<Detection>> {
        texts.iter().map(|t| self.detector.detect(t)).collect()
    }

    /// Detects PII in multiple texts with parallel processing.
    #[cfg(feature = "rayon")]
    pub fn detect_batch_parallel(&self, texts: &[&str]) -> Vec<Vec<Detection>> {
        use rayon::prelude::*;
        texts.par_iter().map(|t| self.detector.detect(t)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_detection() {
        let detector = PiiDetector::new();
        let text = "Contact john@example.com or call 555-123-4567";

        let detections = detector.detect(text);

        assert!(detections.len() >= 2);
        assert!(detections.iter().any(|d| matches!(d.pii_type, PIIType::Email)));
        assert!(detections.iter().any(|d| matches!(d.pii_type, PIIType::Phone)));
    }

    #[test]
    fn test_confidence_filter() {
        let config = DetectorConfig {
            min_confidence: 0.9,
            ..Default::default()
        };
        let detector = PiiDetector::with_config(config);

        let text = "SSN: 123-45-6789"; // High confidence
        let detections = detector.detect(text);

        // Should detect SSN with high confidence
        assert!(!detections.is_empty());
    }

    #[test]
    fn test_risk_level_filter() {
        let config = DetectorConfig {
            min_risk_level: PIIRiskLevel::High,
            ..Default::default()
        };
        let detector = PiiDetector::with_config(config);

        let text = "IP: 192.168.1.1, SSN: 123-45-6789";
        let detections = detector.detect(text);

        // Should only detect SSN (Critical), not IP (Low)
        assert!(detections.iter().any(|d| matches!(d.pii_type, PIIType::Ssn)));
        assert!(!detections.iter().any(|d| matches!(d.pii_type, PIIType::IpAddress)));
    }

    #[test]
    fn test_json_detection() {
        let detector = PiiDetector::new();
        let json = serde_json::json!({
            "user": {
                "name": "John Doe",
                "email": "john@example.com",
                "phone": "555-123-4567"
            }
        });

        let detections = detector.detect_json(&json);

        assert!(detections.len() >= 2);
        assert!(detections.iter().any(|d| d.location.path.as_ref().map_or(false, |p| p.contains("email"))));
    }

    #[test]
    fn test_context_extraction() {
        let config = DetectorConfig {
            context_analysis: true,
            context_window: 20,
            ..Default::default()
        };
        let detector = PiiDetector::with_config(config);

        let text = "Please contact john@example.com for more information.";
        let detections = detector.detect(text);

        assert!(!detections.is_empty());
        assert!(detections[0].context.is_some());
    }

    #[test]
    fn test_detection_stats() {
        let detector = PiiDetector::new();
        let text = "Email: a@b.com, Phone: 555-123-4567, SSN: 123-45-6789";

        let detections = detector.detect(text);
        let stats = detector.stats(&detections);

        assert!(stats.total >= 3);
        assert!(stats.by_type.len() >= 3);
    }
}
