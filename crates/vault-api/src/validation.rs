//! Request validation utilities.

use crate::{ApiError, ApiResult, error::ValidationErrors};
use serde::de::DeserializeOwned;
use validator::Validate;

/// Validates a request body.
pub fn validate_body<T: Validate>(body: &T) -> ApiResult<()> {
    body.validate().map_err(ApiError::from)
}

/// Validates and deserializes JSON.
pub fn validate_json<T: DeserializeOwned + Validate>(json: &str) -> ApiResult<T> {
    let value: T = serde_json::from_str(json)?;
    validate_body(&value)?;
    Ok(value)
}

/// UUID validation.
pub fn validate_uuid(id: &str) -> ApiResult<uuid::Uuid> {
    uuid::Uuid::parse_str(id)
        .map_err(|_| ApiError::BadRequest(format!("Invalid UUID: {}", id)))
}

/// Dataset ID validation.
pub fn validate_dataset_id(id: &str) -> ApiResult<()> {
    if id.is_empty() {
        return Err(ApiError::BadRequest("Dataset ID cannot be empty".into()));
    }
    if id.len() > 128 {
        return Err(ApiError::BadRequest("Dataset ID too long".into()));
    }
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(ApiError::BadRequest(
            "Dataset ID can only contain alphanumeric characters, hyphens, and underscores".into(),
        ));
    }
    Ok(())
}

/// Validates a name field.
pub fn validate_name(name: &str, field_name: &str, min_len: usize, max_len: usize) -> ApiResult<()> {
    if name.len() < min_len {
        return Err(ApiError::BadRequest(format!(
            "{} must be at least {} characters",
            field_name, min_len
        )));
    }
    if name.len() > max_len {
        return Err(ApiError::BadRequest(format!(
            "{} must be at most {} characters",
            field_name, max_len
        )));
    }
    Ok(())
}

/// Validates pagination parameters.
pub fn validate_pagination(page: u32, page_size: u32) -> ApiResult<()> {
    if page == 0 {
        return Err(ApiError::BadRequest("Page must be at least 1".into()));
    }
    if page_size == 0 || page_size > 100 {
        return Err(ApiError::BadRequest("Page size must be between 1 and 100".into()));
    }
    Ok(())
}

/// Validates a JSON path.
pub fn validate_json_path(path: &str) -> ApiResult<()> {
    if path.is_empty() {
        return Err(ApiError::BadRequest("JSON path cannot be empty".into()));
    }
    // Basic validation - starts with $ or root identifier
    if !path.starts_with('$') && !path.starts_with('/') {
        return Err(ApiError::BadRequest("Invalid JSON path format".into()));
    }
    Ok(())
}

/// Validates content type header.
pub fn validate_content_type(content_type: &str, expected: &[&str]) -> ApiResult<()> {
    let content_type_lower = content_type.to_lowercase();
    for expected_type in expected {
        if content_type_lower.starts_with(*expected_type) {
            return Ok(());
        }
    }
    Err(ApiError::BadRequest(format!(
        "Invalid content type '{}', expected one of: {}",
        content_type,
        expected.join(", ")
    )))
}

/// Validation builder for complex validation scenarios.
pub struct Validator {
    errors: ValidationErrors,
}

impl Validator {
    /// Creates a new validator.
    pub fn new() -> Self {
        Self {
            errors: ValidationErrors::new(),
        }
    }

    /// Validates that a field is not empty.
    pub fn required(mut self, field: &str, value: &str) -> Self {
        if value.trim().is_empty() {
            self.errors.add(field, "is required");
        }
        self
    }

    /// Validates that a field is present.
    pub fn required_option<T>(mut self, field: &str, value: &Option<T>) -> Self {
        if value.is_none() {
            self.errors.add(field, "is required");
        }
        self
    }

    /// Validates minimum length.
    pub fn min_length(mut self, field: &str, value: &str, min: usize) -> Self {
        if value.len() < min {
            self.errors.add(field, format!("must be at least {} characters", min));
        }
        self
    }

    /// Validates maximum length.
    pub fn max_length(mut self, field: &str, value: &str, max: usize) -> Self {
        if value.len() > max {
            self.errors.add(field, format!("must be at most {} characters", max));
        }
        self
    }

    /// Validates a numeric range.
    pub fn range<T: PartialOrd + std::fmt::Display>(
        mut self,
        field: &str,
        value: T,
        min: T,
        max: T,
    ) -> Self {
        if value < min || value > max {
            self.errors.add(field, format!("must be between {} and {}", min, max));
        }
        self
    }

    /// Validates using a custom function.
    pub fn custom<F>(mut self, field: &str, f: F) -> Self
    where
        F: FnOnce() -> Option<String>,
    {
        if let Some(error) = f() {
            self.errors.add(field, error);
        }
        self
    }

    /// Validates an email address.
    pub fn email(mut self, field: &str, value: &str) -> Self {
        if !value.is_empty() && !is_valid_email(value) {
            self.errors.add(field, "must be a valid email address");
        }
        self
    }

    /// Validates a URL.
    pub fn url(mut self, field: &str, value: &str) -> Self {
        if !value.is_empty() && url::Url::parse(value).is_err() {
            self.errors.add(field, "must be a valid URL");
        }
        self
    }

    /// Validates a UUID.
    pub fn uuid(mut self, field: &str, value: &str) -> Self {
        if !value.is_empty() && uuid::Uuid::parse_str(value).is_err() {
            self.errors.add(field, "must be a valid UUID");
        }
        self
    }

    /// Validates that a value matches a pattern.
    pub fn pattern(mut self, field: &str, value: &str, pattern: &str) -> Self {
        if let Ok(re) = regex::Regex::new(pattern) {
            if !value.is_empty() && !re.is_match(value) {
                self.errors.add(field, format!("must match pattern: {}", pattern));
            }
        }
        self
    }

    /// Validates that a value is one of the allowed values.
    pub fn one_of(mut self, field: &str, value: &str, allowed: &[&str]) -> Self {
        if !value.is_empty() && !allowed.contains(&value) {
            self.errors.add(
                field,
                format!("must be one of: {}", allowed.join(", ")),
            );
        }
        self
    }

    /// Finishes validation and returns any errors.
    pub fn finish(self) -> ApiResult<()> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(ApiError::ValidationError(self.errors))
        }
    }

    /// Returns true if there are no errors.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

impl Default for Validator {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple email validation.
fn is_valid_email(email: &str) -> bool {
    // Basic check - contains @ with text before and after
    if let Some(at_pos) = email.find('@') {
        let (local, domain) = email.split_at(at_pos);
        let domain = &domain[1..]; // Skip @

        !local.is_empty()
            && !domain.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_uuid() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_uuid("invalid").is_err());
    }

    #[test]
    fn test_validate_dataset_id() {
        assert!(validate_dataset_id("my-dataset").is_ok());
        assert!(validate_dataset_id("dataset_123").is_ok());
        assert!(validate_dataset_id("").is_err());
        assert!(validate_dataset_id("invalid/path").is_err());
    }

    #[test]
    fn test_validate_name() {
        assert!(validate_name("test", "name", 1, 100).is_ok());
        assert!(validate_name("", "name", 1, 100).is_err());
        assert!(validate_name("x".repeat(200).as_str(), "name", 1, 100).is_err());
    }

    #[test]
    fn test_validate_pagination() {
        assert!(validate_pagination(1, 20).is_ok());
        assert!(validate_pagination(0, 20).is_err());
        assert!(validate_pagination(1, 0).is_err());
        assert!(validate_pagination(1, 200).is_err());
    }

    #[test]
    fn test_validator_builder() {
        let result = Validator::new()
            .required("name", "test")
            .min_length("name", "test", 1)
            .max_length("name", "test", 100)
            .finish();

        assert!(result.is_ok());
    }

    #[test]
    fn test_validator_failures() {
        let result = Validator::new()
            .required("name", "")
            .min_length("code", "ab", 3)
            .finish();

        assert!(result.is_err());
    }

    #[test]
    fn test_email_validation() {
        assert!(is_valid_email("test@example.com"));
        assert!(is_valid_email("user.name@domain.co.uk"));
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@domain.com"));
        assert!(!is_valid_email("user@"));
    }

    #[test]
    fn test_validator_email() {
        let result = Validator::new()
            .email("email", "test@example.com")
            .finish();
        assert!(result.is_ok());

        let result = Validator::new()
            .email("email", "invalid")
            .finish();
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_one_of() {
        let result = Validator::new()
            .one_of("status", "active", &["active", "inactive", "pending"])
            .finish();
        assert!(result.is_ok());

        let result = Validator::new()
            .one_of("status", "unknown", &["active", "inactive"])
            .finish();
        assert!(result.is_err());
    }
}
