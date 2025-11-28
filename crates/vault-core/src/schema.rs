//! Schema definitions for data validation.

use crate::{PIIType, SchemaId, TenantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Schema definition for a dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSchema {
    /// Unique schema identifier.
    pub id: SchemaId,

    /// Tenant this schema belongs to.
    pub tenant_id: TenantId,

    /// Schema name.
    pub name: String,

    /// Schema version (semver).
    pub version: String,

    /// Field definitions.
    pub fields: Vec<SchemaField>,

    /// Primary key fields.
    pub primary_key: Option<Vec<String>>,

    /// Foreign key constraints.
    pub foreign_keys: Vec<ForeignKeyConstraint>,

    /// Whether this schema is strict (reject unknown fields).
    pub strict: bool,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl DatasetSchema {
    /// Creates a new schema builder.
    #[must_use]
    pub fn builder() -> SchemaBuilder {
        SchemaBuilder::default()
    }

    /// Validates data against this schema.
    pub fn validate(&self, data: &serde_json::Value) -> Result<(), Vec<SchemaValidationError>> {
        let mut errors = Vec::new();

        if let serde_json::Value::Object(obj) = data {
            // Check required fields
            for field in &self.fields {
                if !field.nullable && !obj.contains_key(&field.name) {
                    errors.push(SchemaValidationError {
                        field: field.name.clone(),
                        constraint: "required".to_string(),
                        message: format!("Required field '{}' is missing", field.name),
                    });
                }
            }

            // Validate field types and constraints
            for (key, value) in obj {
                if let Some(field) = self.fields.iter().find(|f| &f.name == key) {
                    if let Err(field_errors) = field.validate(value) {
                        errors.extend(field_errors);
                    }
                } else if self.strict {
                    errors.push(SchemaValidationError {
                        field: key.clone(),
                        constraint: "unknown_field".to_string(),
                        message: format!("Unknown field '{}' (schema is strict)", key),
                    });
                }
            }
        } else {
            errors.push(SchemaValidationError {
                field: String::new(),
                constraint: "type".to_string(),
                message: "Expected an object".to_string(),
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Returns field by name.
    #[must_use]
    pub fn get_field(&self, name: &str) -> Option<&SchemaField> {
        self.fields.iter().find(|f| f.name == name)
    }

    /// Returns fields with PII classification.
    #[must_use]
    pub fn pii_fields(&self) -> Vec<&SchemaField> {
        self.fields
            .iter()
            .filter(|f| f.pii_classification.is_some())
            .collect()
    }
}

/// Builder for schemas.
#[derive(Debug, Default)]
pub struct SchemaBuilder {
    tenant_id: Option<TenantId>,
    name: Option<String>,
    version: String,
    fields: Vec<SchemaField>,
    primary_key: Option<Vec<String>>,
    foreign_keys: Vec<ForeignKeyConstraint>,
    strict: bool,
}

impl SchemaBuilder {
    /// Sets the tenant ID.
    #[must_use]
    pub fn tenant_id(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Sets the schema name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the schema version.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Adds a field.
    #[must_use]
    pub fn field(mut self, field: SchemaField) -> Self {
        self.fields.push(field);
        self
    }

    /// Sets the primary key.
    #[must_use]
    pub fn primary_key(mut self, fields: Vec<String>) -> Self {
        self.primary_key = Some(fields);
        self
    }

    /// Adds a foreign key constraint.
    #[must_use]
    pub fn foreign_key(mut self, constraint: ForeignKeyConstraint) -> Self {
        self.foreign_keys.push(constraint);
        self
    }

    /// Sets whether the schema is strict.
    #[must_use]
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Builds the schema.
    #[must_use]
    pub fn build(self) -> DatasetSchema {
        let now = Utc::now();
        DatasetSchema {
            id: SchemaId::new(),
            tenant_id: self.tenant_id.expect("tenant_id is required"),
            name: self.name.expect("name is required"),
            version: if self.version.is_empty() {
                "1.0.0".to_string()
            } else {
                self.version
            },
            fields: self.fields,
            primary_key: self.primary_key,
            foreign_keys: self.foreign_keys,
            strict: self.strict,
            created_at: now,
            updated_at: now,
        }
    }
}

/// A field in the schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    /// Field name.
    pub name: String,

    /// Field type.
    pub field_type: FieldType,

    /// Whether the field can be null.
    pub nullable: bool,

    /// Optional description.
    pub description: Option<String>,

    /// Field constraints.
    pub constraints: Vec<FieldConstraint>,

    /// PII classification (if any).
    pub pii_classification: Option<PIIClassification>,

    /// Default value.
    pub default_value: Option<serde_json::Value>,
}

impl SchemaField {
    /// Creates a new field builder.
    #[must_use]
    pub fn builder(name: impl Into<String>, field_type: FieldType) -> SchemaFieldBuilder {
        SchemaFieldBuilder {
            name: name.into(),
            field_type,
            nullable: true,
            description: None,
            constraints: Vec::new(),
            pii_classification: None,
            default_value: None,
        }
    }

    /// Validates a value against this field.
    pub fn validate(&self, value: &serde_json::Value) -> Result<(), Vec<SchemaValidationError>> {
        let mut errors = Vec::new();

        // Check null
        if value.is_null() {
            if self.nullable {
                return Ok(());
            }
            errors.push(SchemaValidationError {
                field: self.name.clone(),
                constraint: "nullable".to_string(),
                message: format!("Field '{}' cannot be null", self.name),
            });
            return Err(errors);
        }

        // Check type
        if !self.field_type.matches(value) {
            errors.push(SchemaValidationError {
                field: self.name.clone(),
                constraint: "type".to_string(),
                message: format!(
                    "Field '{}' expected type {:?}, got {}",
                    self.name,
                    self.field_type,
                    value_type_name(value)
                ),
            });
        }

        // Check constraints
        for constraint in &self.constraints {
            if let Err(e) = constraint.validate(&self.name, value) {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Builder for schema fields.
#[derive(Debug)]
pub struct SchemaFieldBuilder {
    name: String,
    field_type: FieldType,
    nullable: bool,
    description: Option<String>,
    constraints: Vec<FieldConstraint>,
    pii_classification: Option<PIIClassification>,
    default_value: Option<serde_json::Value>,
}

impl SchemaFieldBuilder {
    /// Sets nullable.
    #[must_use]
    pub fn nullable(mut self, nullable: bool) -> Self {
        self.nullable = nullable;
        self
    }

    /// Sets the description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Adds a constraint.
    #[must_use]
    pub fn constraint(mut self, constraint: FieldConstraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Sets PII classification.
    #[must_use]
    pub fn pii(mut self, classification: PIIClassification) -> Self {
        self.pii_classification = Some(classification);
        self
    }

    /// Sets default value.
    #[must_use]
    pub fn default_value(mut self, value: serde_json::Value) -> Self {
        self.default_value = Some(value);
        self
    }

    /// Builds the field.
    #[must_use]
    pub fn build(self) -> SchemaField {
        SchemaField {
            name: self.name,
            field_type: self.field_type,
            nullable: self.nullable,
            description: self.description,
            constraints: self.constraints,
            pii_classification: self.pii_classification,
            default_value: self.default_value,
        }
    }
}

/// Data type for a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FieldType {
    /// String type.
    String,
    /// Integer type.
    Integer,
    /// Floating-point number.
    Float,
    /// Boolean type.
    Boolean,
    /// Timestamp (ISO 8601).
    Timestamp,
    /// Date (YYYY-MM-DD).
    Date,
    /// JSON object.
    Json,
    /// Binary data (base64).
    Binary,
    /// Array of items.
    Array {
        /// Type of array items.
        item_type: Box<FieldType>,
    },
    /// Nested struct.
    Struct {
        /// Fields in the struct.
        fields: Vec<SchemaField>,
    },
    /// Enum type.
    Enum {
        /// Allowed values.
        values: Vec<String>,
    },
}

impl FieldType {
    /// Checks if a JSON value matches this type.
    #[must_use]
    pub fn matches(&self, value: &serde_json::Value) -> bool {
        match (self, value) {
            (Self::String, serde_json::Value::String(_)) => true,
            (Self::Integer, serde_json::Value::Number(n)) => n.is_i64() || n.is_u64(),
            (Self::Float, serde_json::Value::Number(_)) => true,
            (Self::Boolean, serde_json::Value::Bool(_)) => true,
            (Self::Timestamp, serde_json::Value::String(s)) => {
                chrono::DateTime::parse_from_rfc3339(s).is_ok()
            }
            (Self::Date, serde_json::Value::String(s)) => {
                chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
            }
            (Self::Json, serde_json::Value::Object(_)) => true,
            (Self::Binary, serde_json::Value::String(_)) => true, // Assume base64
            (Self::Array { item_type }, serde_json::Value::Array(arr)) => {
                arr.iter().all(|item| item_type.matches(item))
            }
            (Self::Struct { fields: _ }, serde_json::Value::Object(_)) => true,
            (Self::Enum { values }, serde_json::Value::String(s)) => values.contains(s),
            _ => false,
        }
    }
}

/// Constraint on a field value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldConstraint {
    /// Minimum string length.
    MinLength {
        /// Minimum length.
        value: usize,
    },
    /// Maximum string length.
    MaxLength {
        /// Maximum length.
        value: usize,
    },
    /// Regex pattern.
    Pattern {
        /// Regex pattern.
        pattern: String,
    },
    /// Minimum numeric value.
    MinValue {
        /// Minimum value.
        value: f64,
    },
    /// Maximum numeric value.
    MaxValue {
        /// Maximum value.
        value: f64,
    },
    /// Value must be unique.
    Unique,
    /// Value must not be null.
    NotNull,
    /// Value must be one of these.
    OneOf {
        /// Allowed values.
        values: Vec<serde_json::Value>,
    },
}

impl FieldConstraint {
    /// Validates a value against this constraint.
    pub fn validate(
        &self,
        field_name: &str,
        value: &serde_json::Value,
    ) -> Result<(), SchemaValidationError> {
        match self {
            Self::MinLength { value: min } => {
                if let serde_json::Value::String(s) = value {
                    if s.len() < *min {
                        return Err(SchemaValidationError {
                            field: field_name.to_string(),
                            constraint: "min_length".to_string(),
                            message: format!(
                                "Field '{}' must be at least {} characters",
                                field_name, min
                            ),
                        });
                    }
                }
            }
            Self::MaxLength { value: max } => {
                if let serde_json::Value::String(s) = value {
                    if s.len() > *max {
                        return Err(SchemaValidationError {
                            field: field_name.to_string(),
                            constraint: "max_length".to_string(),
                            message: format!(
                                "Field '{}' must be at most {} characters",
                                field_name, max
                            ),
                        });
                    }
                }
            }
            Self::Pattern { pattern } => {
                if let serde_json::Value::String(s) = value {
                    let re = regex::Regex::new(pattern).map_err(|_| SchemaValidationError {
                        field: field_name.to_string(),
                        constraint: "pattern".to_string(),
                        message: format!("Invalid regex pattern: {}", pattern),
                    })?;
                    if !re.is_match(s) {
                        return Err(SchemaValidationError {
                            field: field_name.to_string(),
                            constraint: "pattern".to_string(),
                            message: format!(
                                "Field '{}' does not match pattern {}",
                                field_name, pattern
                            ),
                        });
                    }
                }
            }
            Self::MinValue { value: min } => {
                if let serde_json::Value::Number(n) = value {
                    if let Some(f) = n.as_f64() {
                        if f < *min {
                            return Err(SchemaValidationError {
                                field: field_name.to_string(),
                                constraint: "min_value".to_string(),
                                message: format!(
                                    "Field '{}' must be at least {}",
                                    field_name, min
                                ),
                            });
                        }
                    }
                }
            }
            Self::MaxValue { value: max } => {
                if let serde_json::Value::Number(n) = value {
                    if let Some(f) = n.as_f64() {
                        if f > *max {
                            return Err(SchemaValidationError {
                                field: field_name.to_string(),
                                constraint: "max_value".to_string(),
                                message: format!(
                                    "Field '{}' must be at most {}",
                                    field_name, max
                                ),
                            });
                        }
                    }
                }
            }
            Self::Unique | Self::NotNull => {
                // These are handled elsewhere
            }
            Self::OneOf { values } => {
                if !values.contains(value) {
                    return Err(SchemaValidationError {
                        field: field_name.to_string(),
                        constraint: "one_of".to_string(),
                        message: format!(
                            "Field '{}' must be one of: {:?}",
                            field_name, values
                        ),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Classification of PII sensitivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PIIClassification {
    /// Highly confidential (SSN, credit card).
    HighlyConfidential,
    /// Sensitive (name, address).
    Sensitive,
    /// Internal use only.
    Internal,
    /// Public information.
    Public,
}

impl PIIClassification {
    /// Returns the PII types typically associated with this classification.
    #[must_use]
    pub fn typical_pii_types(&self) -> Vec<PIIType> {
        match self {
            Self::HighlyConfidential => vec![
                PIIType::Ssn,
                PIIType::CreditCard,
                PIIType::BankAccount,
                PIIType::MedicalRecordNumber,
            ],
            Self::Sensitive => vec![
                PIIType::Name,
                PIIType::DateOfBirth,
                PIIType::Address,
                PIIType::PhoneNumber,
            ],
            Self::Internal => vec![PIIType::Email, PIIType::IpAddress],
            Self::Public => vec![],
        }
    }
}

/// Foreign key constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeignKeyConstraint {
    /// Fields in this schema.
    pub fields: Vec<String>,
    /// Referenced schema ID.
    pub referenced_schema: SchemaId,
    /// Fields in the referenced schema.
    pub referenced_fields: Vec<String>,
    /// Action on delete.
    pub on_delete: ReferentialAction,
    /// Action on update.
    pub on_update: ReferentialAction,
}

/// Referential action for foreign keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferentialAction {
    /// Cascade changes.
    Cascade,
    /// Restrict changes.
    Restrict,
    /// Set to null.
    SetNull,
    /// No action.
    NoAction,
}

impl Default for ReferentialAction {
    fn default() -> Self {
        Self::Restrict
    }
}

/// Schema validation error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaValidationError {
    /// Field that failed validation.
    pub field: String,
    /// Constraint that was violated.
    pub constraint: String,
    /// Error message.
    pub message: String,
}

/// Returns a human-readable type name for a JSON value.
fn value_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_validation() {
        let schema = DatasetSchema::builder()
            .tenant_id(TenantId::new())
            .name("test_schema")
            .field(
                SchemaField::builder("name", FieldType::String)
                    .nullable(false)
                    .constraint(FieldConstraint::MinLength { value: 1 })
                    .build(),
            )
            .field(
                SchemaField::builder("age", FieldType::Integer)
                    .nullable(true)
                    .constraint(FieldConstraint::MinValue { value: 0.0 })
                    .build(),
            )
            .build();

        let valid = serde_json::json!({
            "name": "John",
            "age": 30
        });
        assert!(schema.validate(&valid).is_ok());

        let missing_required = serde_json::json!({
            "age": 30
        });
        assert!(schema.validate(&missing_required).is_err());
    }

    #[test]
    fn test_field_type_matching() {
        assert!(FieldType::String.matches(&serde_json::json!("hello")));
        assert!(FieldType::Integer.matches(&serde_json::json!(42)));
        assert!(FieldType::Float.matches(&serde_json::json!(3.14)));
        assert!(FieldType::Boolean.matches(&serde_json::json!(true)));
        assert!(!FieldType::String.matches(&serde_json::json!(42)));
    }
}
