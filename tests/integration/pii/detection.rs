//! PII detection integration tests.

use vault_anonymize::{PiiDetector, DetectorConfig, Detection, PIICategory, ComplianceFramework};
use vault_core::record::PIIType;
use crate::common::pii_samples;

/// Creates a test PII detector with default configuration.
fn create_detector() -> PiiDetector {
    let config = DetectorConfig::default();
    PiiDetector::new(config)
}

/// Tests detecting email addresses.
#[test]
fn test_detect_emails() {
    let detector = create_detector();

    for sample in pii_samples::EMAILS {
        let detections = detector.detect(sample);

        assert!(
            !detections.is_empty(),
            "Failed to detect email in: {}",
            sample
        );

        assert!(
            detections.iter().any(|d| d.pii_type == PIIType::Email),
            "No email detection in: {}",
            sample
        );
    }
}

/// Tests detecting phone numbers.
#[test]
fn test_detect_phone_numbers() {
    let detector = create_detector();

    for sample in pii_samples::PHONES {
        let detections = detector.detect(sample);

        assert!(
            !detections.is_empty(),
            "Failed to detect phone in: {}",
            sample
        );

        assert!(
            detections.iter().any(|d| matches!(d.pii_type, PIIType::Phone | PIIType::PhoneNumber)),
            "No phone detection in: {}",
            sample
        );
    }
}

/// Tests detecting SSNs.
#[test]
fn test_detect_ssns() {
    let detector = create_detector();

    for sample in pii_samples::SSNS {
        let detections = detector.detect(sample);

        assert!(
            !detections.is_empty(),
            "Failed to detect SSN in: {}",
            sample
        );

        assert!(
            detections.iter().any(|d| d.pii_type == PIIType::Ssn),
            "No SSN detection in: {}",
            sample
        );
    }
}

/// Tests detecting credit card numbers.
#[test]
fn test_detect_credit_cards() {
    let detector = create_detector();

    for sample in pii_samples::CREDIT_CARDS {
        let detections = detector.detect(sample);

        assert!(
            !detections.is_empty(),
            "Failed to detect credit card in: {}",
            sample
        );

        assert!(
            detections.iter().any(|d| d.pii_type == PIIType::CreditCard),
            "No credit card detection in: {}",
            sample
        );
    }
}

/// Tests detecting IP addresses.
#[test]
fn test_detect_ip_addresses() {
    let detector = create_detector();

    for sample in pii_samples::IP_ADDRESSES {
        let detections = detector.detect(sample);

        assert!(
            !detections.is_empty(),
            "Failed to detect IP address in: {}",
            sample
        );

        assert!(
            detections.iter().any(|d| d.pii_type == PIIType::IpAddress),
            "No IP address detection in: {}",
            sample
        );
    }
}

/// Tests clean text produces no detections.
#[test]
fn test_no_false_positives() {
    let detector = create_detector();

    for sample in pii_samples::CLEAN_TEXT {
        let detections = detector.detect(sample);

        assert!(
            detections.is_empty(),
            "False positive in clean text: {} - detections: {:?}",
            sample,
            detections
        );
    }
}

/// Tests detecting multiple PII types in one text.
#[test]
fn test_detect_multiple_pii() {
    let detector = create_detector();

    let detections = detector.detect(pii_samples::MIXED_PII);

    // Should detect at least 4 different PII types
    let pii_types: std::collections::HashSet<_> = detections.iter()
        .map(|d| d.pii_type.clone())
        .collect();

    assert!(
        pii_types.len() >= 4,
        "Expected at least 4 different PII types, got {} in text with email, SSN, phone, credit card, IP",
        pii_types.len()
    );
}

/// Tests detection confidence scores.
#[test]
fn test_detection_confidence() {
    let detector = create_detector();

    let detections = detector.detect("Email: test@example.com");

    assert!(!detections.is_empty());

    for detection in detections {
        // Confidence should be between 0 and 1
        assert!(
            detection.confidence >= 0.0 && detection.confidence <= 1.0,
            "Invalid confidence: {}",
            detection.confidence
        );

        // High-quality matches should have high confidence
        if detection.pii_type == PIIType::Email {
            assert!(
                detection.confidence >= 0.9,
                "Email confidence too low: {}",
                detection.confidence
            );
        }
    }
}

/// Tests detection positions are correct.
#[test]
fn test_detection_positions() {
    let detector = create_detector();
    let text = "Contact: test@example.com";

    let detections = detector.detect(text);

    for detection in &detections {
        // Extract the detected value using positions
        let detected_text = &text[detection.start..detection.end];

        // The detected text should match the value
        assert_eq!(
            detected_text, detection.value,
            "Position mismatch: detected '{}' but extracted '{}'",
            detection.value, detected_text
        );
    }
}

/// Tests empty text produces no detections.
#[test]
fn test_empty_text() {
    let detector = create_detector();

    let detections = detector.detect("");

    assert!(detections.is_empty());
}

/// Tests whitespace-only text produces no detections.
#[test]
fn test_whitespace_only() {
    let detector = create_detector();

    let detections = detector.detect("   \n\t\r   ");

    assert!(detections.is_empty());
}

/// Tests Unicode text handling.
#[test]
fn test_unicode_text() {
    let detector = create_detector();

    // Email embedded in Unicode text
    let text = "联系方式: test@example.com 或者发邮件";

    let detections = detector.detect(text);

    assert!(
        detections.iter().any(|d| d.pii_type == PIIType::Email),
        "Failed to detect email in Unicode text"
    );
}

/// Tests PII category classification.
#[test]
fn test_pii_categories() {
    // Test category mappings
    assert_eq!(
        PIICategory::from_pii_type(&PIIType::Email),
        PIICategory::ContactInfo
    );
    assert_eq!(
        PIICategory::from_pii_type(&PIIType::Ssn),
        PIICategory::GovernmentId
    );
    assert_eq!(
        PIICategory::from_pii_type(&PIIType::CreditCard),
        PIICategory::Financial
    );
    assert_eq!(
        PIICategory::from_pii_type(&PIIType::IpAddress),
        PIICategory::OnlineIdentifier
    );
}

/// Tests compliance framework PII types.
#[test]
fn test_compliance_frameworks() {
    // GDPR should require many PII types
    let gdpr_types = ComplianceFramework::Gdpr.required_pii_types();
    assert!(gdpr_types.contains(&PIIType::Email));
    assert!(gdpr_types.contains(&PIIType::Name));
    assert!(gdpr_types.contains(&PIIType::IpAddress));

    // HIPAA should include medical types
    let hipaa_types = ComplianceFramework::Hipaa.required_pii_types();
    assert!(hipaa_types.contains(&PIIType::MedicalRecordNumber));
    assert!(hipaa_types.contains(&PIIType::HealthInfo));

    // PCI-DSS should focus on financial
    let pci_types = ComplianceFramework::PciDss.required_pii_types();
    assert!(pci_types.contains(&PIIType::CreditCard));
}

/// Tests minimum confidence threshold.
#[test]
fn test_confidence_threshold() {
    let config = DetectorConfig {
        min_confidence: 0.9,
        ..Default::default()
    };
    let detector = PiiDetector::new(config);

    // Should only return high-confidence matches
    let detections = detector.detect("test@example.com");

    for detection in detections {
        assert!(
            detection.confidence >= 0.9,
            "Detection below threshold: {}",
            detection.confidence
        );
    }
}

/// Tests context-aware detection.
#[test]
fn test_context_detection() {
    let config = DetectorConfig {
        context_analysis: true,
        context_window: 50,
        ..Default::default()
    };
    let detector = PiiDetector::new(config);

    // "Email:" prefix should increase confidence
    let with_context = "Email: test@example.com";
    let without_context = "test@example.com";

    let detections_with = detector.detect(with_context);
    let detections_without = detector.detect(without_context);

    // Both should detect email, context may affect confidence
    assert!(!detections_with.is_empty());
    assert!(!detections_without.is_empty());
}

/// Tests detection of edge cases.
#[test]
fn test_edge_cases() {
    let detector = create_detector();

    // Email at start of text
    let detections = detector.detect("test@example.com is my email");
    assert!(detections.iter().any(|d| d.pii_type == PIIType::Email));

    // Email at end of text
    let detections = detector.detect("My email is test@example.com");
    assert!(detections.iter().any(|d| d.pii_type == PIIType::Email));

    // Multiple emails in same text
    let detections = detector.detect("Contact a@b.com or c@d.org");
    let email_count = detections.iter()
        .filter(|d| d.pii_type == PIIType::Email)
        .count();
    assert!(email_count >= 2, "Expected at least 2 emails, got {}", email_count);
}

/// Tests detection performance.
#[test]
fn test_detection_performance() {
    let detector = create_detector();

    // Generate a large text with some PII
    let text = format!(
        "{}\n{}\n{}",
        "A".repeat(10000),
        "Contact: test@example.com",
        "B".repeat(10000)
    );

    let start = std::time::Instant::now();
    let detections = detector.detect(&text);
    let elapsed = start.elapsed();

    // Should detect email
    assert!(detections.iter().any(|d| d.pii_type == PIIType::Email));

    // Should complete in reasonable time (< 1 second)
    assert!(
        elapsed.as_secs() < 1,
        "Detection took too long: {:?}",
        elapsed
    );
}

/// Tests detector is thread-safe.
#[test]
fn test_detector_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    let detector = Arc::new(create_detector());
    let mut handles = vec![];

    for i in 0..10 {
        let detector = detector.clone();
        handles.push(thread::spawn(move || {
            let text = format!("Email {}: user{}@example.com", i, i);
            detector.detect(&text)
        }));
    }

    for handle in handles {
        let detections = handle.join().expect("Thread panicked");
        assert!(!detections.is_empty());
    }
}
