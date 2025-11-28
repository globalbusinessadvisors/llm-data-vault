//! Input validation and sanitization.
//!
//! Provides comprehensive input validation including:
//! - XSS prevention
//! - SQL injection detection
//! - Path traversal detection
//! - Size limit enforcement
//! - Character encoding validation
//! - Pattern-based blocking

use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::InputConfig;
use crate::error::{Result, ThreatLevel};

/// Result of input validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Whether validation passed.
    pub valid: bool,
    /// Validation errors.
    pub errors: Vec<ValidationError>,
    /// Warnings (non-fatal issues).
    pub warnings: Vec<String>,
    /// Sanitized value (if applicable).
    pub sanitized: Option<String>,
}

impl ValidationResult {
    /// Creates a successful validation result.
    #[must_use]
    pub fn success() -> Self {
        Self {
            valid: true,
            errors: vec![],
            warnings: vec![],
            sanitized: None,
        }
    }

    /// Creates a successful validation result with sanitized value.
    #[must_use]
    pub fn success_with_sanitized(sanitized: String) -> Self {
        Self {
            valid: true,
            errors: vec![],
            warnings: vec![],
            sanitized: Some(sanitized),
        }
    }

    /// Creates a failed validation result.
    #[must_use]
    pub fn failure(error: ValidationError) -> Self {
        Self {
            valid: false,
            errors: vec![error],
            warnings: vec![],
            sanitized: None,
        }
    }

    /// Adds an error to the result.
    pub fn add_error(&mut self, error: ValidationError) {
        self.valid = false;
        self.errors.push(error);
    }

    /// Adds a warning to the result.
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
}

/// A validation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Field that failed validation.
    pub field: Option<String>,
    /// Error message.
    pub message: String,
    /// Validation rule that failed.
    pub rule: String,
    /// Threat level of the violation.
    pub threat_level: Option<ThreatLevel>,
}

impl ValidationError {
    /// Creates a new validation error.
    #[must_use]
    pub fn new(message: impl Into<String>, rule: impl Into<String>) -> Self {
        Self {
            field: None,
            message: message.into(),
            rule: rule.into(),
            threat_level: None,
        }
    }

    /// Creates a validation error for a specific field.
    #[must_use]
    pub fn for_field(
        field: impl Into<String>,
        message: impl Into<String>,
        rule: impl Into<String>,
    ) -> Self {
        Self {
            field: Some(field.into()),
            message: message.into(),
            rule: rule.into(),
            threat_level: None,
        }
    }

    /// Sets the threat level.
    #[must_use]
    pub fn with_threat_level(mut self, level: ThreatLevel) -> Self {
        self.threat_level = Some(level);
        self
    }
}

/// Sanitization rules for input processing.
#[derive(Debug, Clone, Default)]
pub struct SanitizationRules {
    /// Strip HTML tags.
    pub strip_html: bool,
    /// Strip null bytes.
    pub strip_null_bytes: bool,
    /// Normalize whitespace.
    pub normalize_whitespace: bool,
    /// Trim leading/trailing whitespace.
    pub trim: bool,
    /// Convert to lowercase.
    pub lowercase: bool,
    /// Maximum length after sanitization.
    pub max_length: Option<usize>,
    /// Allowed characters (regex pattern).
    pub allowed_chars: Option<String>,
}

impl SanitizationRules {
    /// Creates strict sanitization rules.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            strip_html: true,
            strip_null_bytes: true,
            normalize_whitespace: true,
            trim: true,
            lowercase: false,
            max_length: Some(10000),
            allowed_chars: None,
        }
    }

    /// Creates minimal sanitization rules.
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            strip_null_bytes: true,
            trim: true,
            ..Default::default()
        }
    }
}

/// Input validator for security checks.
pub struct InputValidator {
    config: InputConfig,
    sql_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    path_traversal_patterns: Vec<Regex>,
    blocked_patterns: Vec<Regex>,
}

impl InputValidator {
    /// Creates a new input validator with the given configuration.
    #[must_use]
    pub fn new(config: InputConfig) -> Self {
        let sql_patterns = Self::compile_sql_patterns();
        let xss_patterns = Self::compile_xss_patterns();
        let path_traversal_patterns = Self::compile_path_traversal_patterns();
        let blocked_patterns = config
            .blocked_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        Self {
            config,
            sql_patterns,
            xss_patterns,
            path_traversal_patterns,
            blocked_patterns,
        }
    }

    /// Validates a string input.
    pub fn validate_string(&self, input: &str, field: Option<&str>) -> ValidationResult {
        let mut result = ValidationResult::success();

        // Check length
        if input.len() > self.config.max_string_length {
            result.add_error(
                ValidationError::for_field(
                    field.unwrap_or("input"),
                    format!(
                        "String exceeds maximum length of {} bytes",
                        self.config.max_string_length
                    ),
                    "max_length",
                )
                .with_threat_level(ThreatLevel::Low),
            );
        }

        // Validate UTF-8 if required
        if self.config.validate_utf8 && !input.is_ascii() {
            // Already valid UTF-8 since it's a &str, but check for suspicious sequences
            if input.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
                result.add_warning("Input contains control characters".to_string());
            }
        }

        // Check for null bytes
        if self.config.strip_null_bytes && input.contains('\0') {
            result.add_error(
                ValidationError::for_field(
                    field.unwrap_or("input"),
                    "Input contains null bytes",
                    "null_bytes",
                )
                .with_threat_level(ThreatLevel::Medium),
            );
        }

        // Check for SQL injection
        if self.detect_sql_injection(input) {
            warn!("Potential SQL injection detected in field {:?}", field);
            result.add_error(
                ValidationError::for_field(
                    field.unwrap_or("input"),
                    "Potential SQL injection detected",
                    "sql_injection",
                )
                .with_threat_level(ThreatLevel::Critical),
            );
        }

        // Check for XSS
        if self.detect_xss(input) {
            warn!("Potential XSS attack detected in field {:?}", field);
            result.add_error(
                ValidationError::for_field(
                    field.unwrap_or("input"),
                    "Potential XSS attack detected",
                    "xss",
                )
                .with_threat_level(ThreatLevel::High),
            );
        }

        // Check for path traversal
        if self.detect_path_traversal(input) {
            warn!("Potential path traversal detected in field {:?}", field);
            result.add_error(
                ValidationError::for_field(
                    field.unwrap_or("input"),
                    "Potential path traversal detected",
                    "path_traversal",
                )
                .with_threat_level(ThreatLevel::High),
            );
        }

        // Check blocked patterns
        for pattern in &self.blocked_patterns {
            if pattern.is_match(input) {
                result.add_error(
                    ValidationError::for_field(
                        field.unwrap_or("input"),
                        "Input matches blocked pattern",
                        "blocked_pattern",
                    )
                    .with_threat_level(ThreatLevel::Medium),
                );
            }
        }

        result
    }

    /// Validates JSON input.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate_json(&self, json: &serde_json::Value, depth: usize) -> Result<ValidationResult> {
        if depth > self.config.max_json_depth {
            return Ok(ValidationResult::failure(
                ValidationError::new(
                    format!("JSON depth exceeds maximum of {}", self.config.max_json_depth),
                    "max_depth",
                )
                .with_threat_level(ThreatLevel::Low),
            ));
        }

        let mut result = ValidationResult::success();

        match json {
            serde_json::Value::String(s) => {
                let string_result = self.validate_string(s, None);
                if !string_result.valid {
                    for error in string_result.errors {
                        result.add_error(error);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                if arr.len() > self.config.max_array_length {
                    result.add_error(
                        ValidationError::new(
                            format!(
                                "Array length {} exceeds maximum of {}",
                                arr.len(),
                                self.config.max_array_length
                            ),
                            "max_array_length",
                        )
                        .with_threat_level(ThreatLevel::Low),
                    );
                }

                for item in arr {
                    let item_result = self.validate_json(item, depth + 1)?;
                    if !item_result.valid {
                        for error in item_result.errors {
                            result.add_error(error);
                        }
                    }
                }
            }
            serde_json::Value::Object(obj) => {
                for (key, value) in obj {
                    // Validate key
                    let key_result = self.validate_string(key, Some("object_key"));
                    if !key_result.valid {
                        for error in key_result.errors {
                            result.add_error(error);
                        }
                    }

                    // Validate value
                    let value_result = self.validate_json(value, depth + 1)?;
                    if !value_result.valid {
                        for error in value_result.errors {
                            result.add_error(error);
                        }
                    }
                }
            }
            _ => {} // Numbers, booleans, null are safe
        }

        Ok(result)
    }

    /// Validates request body size.
    pub fn validate_body_size(&self, size: usize) -> ValidationResult {
        if size > self.config.max_body_size {
            ValidationResult::failure(
                ValidationError::new(
                    format!(
                        "Body size {} exceeds maximum of {} bytes",
                        size, self.config.max_body_size
                    ),
                    "max_body_size",
                )
                .with_threat_level(ThreatLevel::Low),
            )
        } else {
            ValidationResult::success()
        }
    }

    /// Validates content type.
    pub fn validate_content_type(&self, content_type: &str) -> ValidationResult {
        let base_type = content_type.split(';').next().unwrap_or("").trim();

        if self.config.allowed_content_types.iter().any(|t| t == base_type) {
            ValidationResult::success()
        } else {
            ValidationResult::failure(
                ValidationError::new(
                    format!("Content type '{}' is not allowed", content_type),
                    "content_type",
                )
                .with_threat_level(ThreatLevel::Low),
            )
        }
    }

    /// Sanitizes a string according to the given rules.
    #[must_use]
    pub fn sanitize(&self, input: &str, rules: &SanitizationRules) -> String {
        let mut result = input.to_string();

        // Strip null bytes
        if rules.strip_null_bytes {
            result = result.replace('\0', "");
        }

        // Strip HTML
        if rules.strip_html {
            result = self.strip_html_tags(&result);
        }

        // Normalize whitespace
        if rules.normalize_whitespace {
            result = self.normalize_whitespace(&result);
        }

        // Trim
        if rules.trim {
            result = result.trim().to_string();
        }

        // Lowercase
        if rules.lowercase {
            result = result.to_lowercase();
        }

        // Apply max length
        if let Some(max_len) = rules.max_length {
            if result.len() > max_len {
                result = result.chars().take(max_len).collect();
            }
        }

        // Filter allowed characters
        if let Some(ref pattern) = rules.allowed_chars {
            if let Ok(regex) = Regex::new(pattern) {
                result = regex.find_iter(&result)
                    .map(|m| m.as_str())
                    .collect();
            }
        }

        result
    }

    /// Validates an email address.
    pub fn validate_email(&self, email: &str) -> ValidationResult {
        // Basic email validation
        let email_regex = Regex::new(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        ).unwrap();

        if !email_regex.is_match(email) {
            return ValidationResult::failure(
                ValidationError::new("Invalid email format", "email_format"),
            );
        }

        // Check for suspicious patterns
        let result = self.validate_string(email, Some("email"));
        if !result.valid {
            return result;
        }

        // Additional email-specific checks
        if email.len() > 254 {
            return ValidationResult::failure(
                ValidationError::new("Email exceeds maximum length", "email_length"),
            );
        }

        ValidationResult::success()
    }

    /// Validates a URL.
    pub fn validate_url(&self, url: &str) -> ValidationResult {
        // Parse URL
        let parsed = match url::Url::parse(url) {
            Ok(u) => u,
            Err(_) => {
                return ValidationResult::failure(
                    ValidationError::new("Invalid URL format", "url_format"),
                );
            }
        };

        // Check scheme
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return ValidationResult::failure(
                ValidationError::new(
                    format!("URL scheme '{}' is not allowed", scheme),
                    "url_scheme",
                ),
            );
        }

        // Check for suspicious patterns
        let result = self.validate_string(url, Some("url"));
        if !result.valid {
            return result;
        }

        ValidationResult::success()
    }

    /// Validates a filename.
    pub fn validate_filename(&self, filename: &str) -> ValidationResult {
        // Check for path traversal
        if self.detect_path_traversal(filename) {
            return ValidationResult::failure(
                ValidationError::new("Filename contains path traversal", "path_traversal")
                    .with_threat_level(ThreatLevel::High),
            );
        }

        // Check for dangerous characters
        let dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0'];
        for c in dangerous_chars {
            if filename.contains(c) {
                return ValidationResult::failure(
                    ValidationError::new(
                        format!("Filename contains dangerous character: {}", c),
                        "dangerous_char",
                    ),
                );
            }
        }

        // Check length
        if filename.len() > 255 {
            return ValidationResult::failure(
                ValidationError::new("Filename exceeds maximum length", "filename_length"),
            );
        }

        // Check for hidden files (Unix-style)
        if filename.starts_with('.') {
            return ValidationResult::failure(
                ValidationError::new("Hidden filenames are not allowed", "hidden_file"),
            );
        }

        ValidationResult::success()
    }

    // Private helper methods

    fn compile_sql_patterns() -> Vec<Regex> {
        let patterns = [
            r"(?i)\b(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)",
            r"(?i)\b(drop\s+table|alter\s+table|create\s+table|truncate\s+table)",
            r"(?i)\b(or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*')",
            r"(?i)\b(exec|execute|xp_|sp_)",
            r"(?i)--\s*$|/\*.*\*/",
            r"(?i)\b(waitfor\s+delay|benchmark\s*\(|sleep\s*\()",
            r"(?i)'\s*(;|--)",
        ];

        patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect()
    }

    fn compile_xss_patterns() -> Vec<Regex> {
        let patterns = [
            r#"(?i)<script[^>]*>"#,
            r#"(?i)</script>"#,
            r#"(?i)javascript\s*:"#,
            r#"(?i)on\w+\s*="#,
            r#"(?i)<iframe[^>]*>"#,
            r#"(?i)<object[^>]*>"#,
            r#"(?i)<embed[^>]*>"#,
            r#"(?i)<link[^>]*>"#,
            r#"(?i)<meta[^>]*>"#,
            r#"(?i)expression\s*\("#,
            r#"(?i)url\s*\(\s*['"]?\s*javascript:"#,
            r#"(?i)data\s*:\s*text/html"#,
            r#"(?i)vbscript\s*:"#,
        ];

        patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect()
    }

    fn compile_path_traversal_patterns() -> Vec<Regex> {
        let patterns = [
            r#"\.\.\/"#,
            r#"\.\.\\"#,
            r#"%2e%2e/"#,
            r#"%2e%2e\\"#,
            r#"\.\.%2f"#,
            r#"\.\.%5c"#,
            r#"%252e%252e/"#,
            r#"\.%00\."#,
        ];

        patterns
            .iter()
            .filter_map(|p| Regex::new(&format!("(?i){}", p)).ok())
            .collect()
    }

    fn detect_sql_injection(&self, input: &str) -> bool {
        self.sql_patterns.iter().any(|p| p.is_match(input))
    }

    fn detect_xss(&self, input: &str) -> bool {
        self.xss_patterns.iter().any(|p| p.is_match(input))
    }

    fn detect_path_traversal(&self, input: &str) -> bool {
        self.path_traversal_patterns.iter().any(|p| p.is_match(input))
    }

    fn strip_html_tags(&self, input: &str) -> String {
        let tag_regex = Regex::new(r"<[^>]*>").unwrap();
        tag_regex.replace_all(input, "").to_string()
    }

    fn normalize_whitespace(&self, input: &str) -> String {
        let ws_regex = Regex::new(r#"\s+"#).unwrap();
        ws_regex.replace_all(input, " ").to_string()
    }
}

impl std::fmt::Debug for InputValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InputValidator")
            .field("config", &self.config)
            .field("sql_patterns_count", &self.sql_patterns.len())
            .field("xss_patterns_count", &self.xss_patterns.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validator() -> InputValidator {
        InputValidator::new(InputConfig::default())
    }

    #[test]
    fn test_sql_injection_detection() {
        let validator = test_validator();

        let malicious_inputs = [
            "'; DROP TABLE users; --",
            "1 OR 1=1",
            "UNION SELECT * FROM passwords",
            "'; EXEC xp_cmdshell('whoami'); --",
        ];

        for input in malicious_inputs {
            let result = validator.validate_string(input, Some("test"));
            assert!(!result.valid, "Should detect SQL injection in: {}", input);
        }
    }

    #[test]
    fn test_xss_detection() {
        let validator = test_validator();

        let malicious_inputs = [
            "<script>alert('xss')</script>",
            "<img onerror='alert(1)' src='x'>",
            "javascript:alert(1)",
            "<iframe src='evil.com'></iframe>",
        ];

        for input in malicious_inputs {
            let result = validator.validate_string(input, Some("test"));
            assert!(!result.valid, "Should detect XSS in: {}", input);
        }
    }

    #[test]
    fn test_path_traversal_detection() {
        let validator = test_validator();

        let malicious_inputs = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32",
            "%2e%2e/etc/passwd",
            "....//....//etc/passwd",
        ];

        for input in malicious_inputs {
            let result = validator.validate_string(input, Some("test"));
            assert!(!result.valid, "Should detect path traversal in: {}", input);
        }
    }

    #[test]
    fn test_sanitization() {
        let validator = test_validator();
        let rules = SanitizationRules::strict();

        let input = "  <script>alert('xss')</script>  Hello   World  ";
        let sanitized = validator.sanitize(input, &rules);

        assert!(!sanitized.contains("<script>"));
        assert!(!sanitized.contains("</script>"));
        assert!(sanitized.starts_with("alert"));
        assert!(!sanitized.contains("  ")); // No double spaces
    }

    #[test]
    fn test_email_validation() {
        let validator = test_validator();

        assert!(validator.validate_email("test@example.com").valid);
        assert!(validator.validate_email("user.name+tag@domain.co.uk").valid);
        assert!(!validator.validate_email("invalid-email").valid);
        assert!(!validator.validate_email("@example.com").valid);
    }

    #[test]
    fn test_filename_validation() {
        let validator = test_validator();

        assert!(validator.validate_filename("document.pdf").valid);
        assert!(!validator.validate_filename("../etc/passwd").valid);
        assert!(!validator.validate_filename("file:name.txt").valid);
        assert!(!validator.validate_filename(".hidden").valid);
    }

    #[test]
    fn test_json_validation() {
        let validator = test_validator();

        let valid_json = serde_json::json!({
            "name": "test",
            "value": 123
        });

        let result = validator.validate_json(&valid_json, 0).unwrap();
        assert!(result.valid);

        let malicious_json = serde_json::json!({
            "name": "<script>alert('xss')</script>"
        });

        let result = validator.validate_json(&malicious_json, 0).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_safe_input() {
        let validator = test_validator();

        let safe_inputs = [
            "Hello, World!",
            "This is a normal sentence.",
            "user@example.com",
            "SELECT your favorite color:",
        ];

        for input in safe_inputs {
            let result = validator.validate_string(input, Some("test"));
            assert!(result.valid, "Should allow safe input: {}", input);
        }
    }
}
