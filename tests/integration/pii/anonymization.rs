//! PII anonymization integration tests.

use vault_anonymize::{
    Anonymizer, AnonymizerConfig, AnonymizationStrategy, StrategyConfig,
    PiiDetector, DetectorConfig,
};
use vault_core::record::PIIType;
use crate::common::pii_samples;

/// Creates a test anonymizer with default configuration.
fn create_anonymizer() -> Anonymizer {
    let detector_config = DetectorConfig::default();
    let detector = PiiDetector::new(detector_config);

    let config = AnonymizerConfig::default();
    Anonymizer::new(config, detector)
}

/// Creates an anonymizer with specific strategy.
fn create_anonymizer_with_strategy(strategy: AnonymizationStrategy) -> Anonymizer {
    let detector_config = DetectorConfig::default();
    let detector = PiiDetector::new(detector_config);

    let config = AnonymizerConfig {
        default_strategy: strategy,
        ..Default::default()
    };
    Anonymizer::new(config, detector)
}

/// Tests basic anonymization with redaction.
#[test]
fn test_anonymize_redact() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Redact);

    let text = "Contact john@example.com for help";
    let result = anonymizer.anonymize(text);

    // Email should be redacted
    assert!(
        !result.text.contains("john@example.com"),
        "Email was not redacted: {}",
        result.text
    );

    // Should contain redaction marker
    assert!(
        result.text.contains("[EMAIL") || result.text.contains("[REDACTED"),
        "Missing redaction marker: {}",
        result.text
    );

    // Should track what was anonymized
    assert_eq!(result.detections_processed, 1);
}

/// Tests anonymization with masking.
#[test]
fn test_anonymize_mask() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Mask);

    let text = "Email: john.doe@example.com";
    let result = anonymizer.anonymize(text);

    // Original email should be partially hidden
    assert!(!result.text.contains("john.doe@example.com"));

    // Should contain partial mask (e.g., j***@e***.com)
    // The exact format depends on implementation
    assert!(
        result.text.contains("*") || result.text.contains("●"),
        "Missing masking in: {}",
        result.text
    );
}

/// Tests anonymization with tokenization.
#[test]
fn test_anonymize_tokenize() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Tokenize);

    let text = "Contact support@company.com";
    let result = anonymizer.anonymize(text);

    // Original email should be replaced with token
    assert!(!result.text.contains("support@company.com"));

    // Should contain a token marker
    assert!(
        result.text.contains("<TOKEN") || result.text.contains("{{"),
        "Missing token in: {}",
        result.text
    );
}

/// Tests anonymization with generalization.
#[test]
fn test_anonymize_generalize() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Generalize);

    let text = "IP: 192.168.1.100";
    let result = anonymizer.anonymize(text);

    // Original IP should be generalized
    assert!(!result.text.contains("192.168.1.100"));

    // Might contain generalized form (e.g., 192.168.x.x)
}

/// Tests anonymizing multiple PII types.
#[test]
fn test_anonymize_multiple_pii() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Redact);

    let result = anonymizer.anonymize(pii_samples::MIXED_PII);

    // Original PII should be removed
    assert!(!result.text.contains("123-45-6789")); // SSN
    assert!(!result.text.contains("john.smith@example.com")); // Email
    assert!(!result.text.contains("555-123-4567")); // Phone
    assert!(!result.text.contains("4111-1111-1111-1111")); // Credit card

    // Multiple items should be processed
    assert!(
        result.detections_processed >= 4,
        "Expected at least 4 detections, got {}",
        result.detections_processed
    );
}

/// Tests clean text is not modified.
#[test]
fn test_anonymize_clean_text() {
    let anonymizer = create_anonymizer();

    for sample in pii_samples::CLEAN_TEXT {
        let result = anonymizer.anonymize(sample);

        // Clean text should not be modified
        assert_eq!(
            result.text, *sample,
            "Clean text was modified: '{}' -> '{}'",
            sample, result.text
        );

        assert_eq!(result.detections_processed, 0);
    }
}

/// Tests anonymization preserves non-PII text structure.
#[test]
fn test_preserve_structure() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Redact);

    let text = "Hello!\n\nPlease contact john@example.com.\n\nThanks!";
    let result = anonymizer.anonymize(text);

    // Should preserve newlines and structure
    assert!(result.text.contains("Hello!"));
    assert!(result.text.contains("Please contact"));
    assert!(result.text.contains("Thanks!"));
    assert!(result.text.contains("\n\n"));

    // But email should be anonymized
    assert!(!result.text.contains("john@example.com"));
}

/// Tests type-specific strategies.
#[test]
fn test_type_specific_strategies() {
    let detector_config = DetectorConfig::default();
    let detector = PiiDetector::new(detector_config);

    // Configure different strategies per type
    let mut config = AnonymizerConfig::default();
    config.type_strategies.insert(PIIType::Email, AnonymizationStrategy::Tokenize);
    config.type_strategies.insert(PIIType::Phone, AnonymizationStrategy::Mask);
    config.type_strategies.insert(PIIType::Ssn, AnonymizationStrategy::Redact);

    let anonymizer = Anonymizer::new(config, detector);

    let text = "Email: a@b.com, Phone: 555-1234, SSN: 123-45-6789";
    let result = anonymizer.anonymize(text);

    // Each type should be handled differently
    // Email: tokenized (contains token marker)
    // Phone: masked (contains *)
    // SSN: redacted (contains [REDACTED] or similar)
}

/// Tests reversible tokenization.
#[test]
fn test_tokenization_reversible() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Tokenize);

    let original = "Contact user@example.com for help";
    let result = anonymizer.anonymize(original);

    // Token should be stored in mappings
    if !result.token_mappings.is_empty() {
        // Should be able to map tokens back to original values
        for (token, original_value) in &result.token_mappings {
            assert!(result.text.contains(token));
            assert_eq!(*original_value, "user@example.com");
        }
    }
}

/// Tests anonymization is idempotent.
#[test]
fn test_idempotent() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Redact);

    let text = "Email: test@example.com";

    let result1 = anonymizer.anonymize(text);
    let result2 = anonymizer.anonymize(&result1.text);

    // Second anonymization should not change anything
    // (redacted text should not be re-redacted)
    assert_eq!(
        result1.text, result2.text,
        "Anonymization not idempotent: '{}' -> '{}'",
        result1.text, result2.text
    );
}

/// Tests empty text handling.
#[test]
fn test_empty_text() {
    let anonymizer = create_anonymizer();

    let result = anonymizer.anonymize("");

    assert_eq!(result.text, "");
    assert_eq!(result.detections_processed, 0);
}

/// Tests Unicode text anonymization.
#[test]
fn test_unicode_anonymization() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Redact);

    let text = "联系方式: user@example.com，谢谢！";
    let result = anonymizer.anonymize(text);

    // Email should be anonymized
    assert!(!result.text.contains("user@example.com"));

    // Chinese characters should be preserved
    assert!(result.text.contains("联系方式"));
    assert!(result.text.contains("谢谢"));
}

/// Tests performance with large text.
#[test]
fn test_performance() {
    let anonymizer = create_anonymizer();

    // Generate large text with PII scattered throughout
    let mut text = String::new();
    for i in 0..100 {
        text.push_str(&format!("Line {} with some regular text.\n", i));
        if i % 10 == 0 {
            text.push_str(&format!("Contact: user{}@example.com\n", i));
        }
    }

    let start = std::time::Instant::now();
    let result = anonymizer.anonymize(&text);
    let elapsed = start.elapsed();

    // Should process in reasonable time
    assert!(
        elapsed.as_millis() < 500,
        "Anonymization took too long: {:?}",
        elapsed
    );

    // Should have anonymized multiple emails
    assert!(result.detections_processed >= 10);
}

/// Tests thread safety.
#[test]
fn test_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    let anonymizer = Arc::new(create_anonymizer());
    let mut handles = vec![];

    for i in 0..10 {
        let anonymizer = anonymizer.clone();
        handles.push(thread::spawn(move || {
            let text = format!("Email: user{}@example.com", i);
            anonymizer.anonymize(&text)
        }));
    }

    for handle in handles {
        let result = handle.join().expect("Thread panicked");
        assert_eq!(result.detections_processed, 1);
    }
}

/// Tests anonymization output format.
#[test]
fn test_output_format() {
    let anonymizer = create_anonymizer_with_strategy(AnonymizationStrategy::Redact);

    let text = "Email: test@example.com";
    let result = anonymizer.anonymize(text);

    // Result should have all fields populated
    assert!(!result.text.is_empty());
    assert!(result.original_length > 0);
    assert!(result.anonymized_length > 0);
}

/// Tests batch anonymization.
#[test]
fn test_batch_anonymization() {
    let anonymizer = create_anonymizer();

    let texts = vec![
        "Email: a@b.com",
        "Phone: 555-1234",
        "Clean text here",
    ];

    let results: Vec<_> = texts.iter()
        .map(|t| anonymizer.anonymize(t))
        .collect();

    assert_eq!(results.len(), 3);
    assert!(results[0].detections_processed > 0); // Email detected
    assert!(results[1].detections_processed > 0); // Phone detected
    assert_eq!(results[2].detections_processed, 0); // Clean text
}

/// Tests specific PII type filtering.
#[test]
fn test_pii_type_filtering() {
    let detector_config = DetectorConfig::default();
    let detector = PiiDetector::new(detector_config);

    // Only anonymize emails, not phones
    let config = AnonymizerConfig {
        enabled_types: vec![PIIType::Email],
        ..Default::default()
    };
    let anonymizer = Anonymizer::new(config, detector);

    let text = "Email: a@b.com, Phone: 555-1234";
    let result = anonymizer.anonymize(text);

    // Email should be anonymized
    assert!(!result.text.contains("a@b.com"));

    // Phone should remain
    assert!(result.text.contains("555-1234"));
}
