//! Metadata types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Custom metadata container.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metadata {
    /// Key-value pairs.
    #[serde(flatten)]
    pub fields: HashMap<String, serde_json::Value>,
}

impl Metadata {
    /// Creates new metadata.
    #[must_use]
    pub fn new(fields: HashMap<String, serde_json::Value>) -> Self {
        Self { fields }
    }

    /// Creates empty metadata.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Gets a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.fields.get(key)
    }

    /// Gets a string value.
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.fields.get(key).and_then(|v| v.as_str())
    }

    /// Gets an integer value.
    #[must_use]
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.fields.get(key).and_then(|v| v.as_i64())
    }

    /// Gets a boolean value.
    #[must_use]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.fields.get(key).and_then(|v| v.as_bool())
    }

    /// Sets a value.
    pub fn set(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.fields.insert(key.into(), value);
    }

    /// Sets a string value.
    pub fn set_str(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields
            .insert(key.into(), serde_json::Value::String(value.into()));
    }

    /// Removes a value.
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.fields.remove(key)
    }

    /// Checks if a key exists.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns true if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Merges another metadata into this one.
    pub fn merge(&mut self, other: Metadata) {
        self.fields.extend(other.fields);
    }
}

impl From<HashMap<String, serde_json::Value>> for Metadata {
    fn from(fields: HashMap<String, serde_json::Value>) -> Self {
        Self::new(fields)
    }
}

impl FromIterator<(String, serde_json::Value)> for Metadata {
    fn from_iter<T: IntoIterator<Item = (String, serde_json::Value)>>(iter: T) -> Self {
        Self {
            fields: iter.into_iter().collect(),
        }
    }
}

/// File format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    /// JSON format.
    Json,
    /// JSON Lines format.
    Jsonl,
    /// CSV format.
    Csv,
    /// Parquet format.
    Parquet,
    /// Apache Avro format.
    Avro,
    /// Apache Arrow format.
    Arrow,
    /// Text format.
    Text,
    /// Binary format.
    Binary,
}

impl FileFormat {
    /// Returns the MIME type for this format.
    #[must_use]
    pub const fn mime_type(&self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Jsonl => "application/x-ndjson",
            Self::Csv => "text/csv",
            Self::Parquet => "application/vnd.apache.parquet",
            Self::Avro => "application/avro",
            Self::Arrow => "application/vnd.apache.arrow.file",
            Self::Text => "text/plain",
            Self::Binary => "application/octet-stream",
        }
    }

    /// Returns the file extension for this format.
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Csv => "csv",
            Self::Parquet => "parquet",
            Self::Avro => "avro",
            Self::Arrow => "arrow",
            Self::Text => "txt",
            Self::Binary => "bin",
        }
    }
}

/// Compression type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionType {
    /// No compression.
    None,
    /// Gzip compression.
    Gzip,
    /// Zstandard compression.
    Zstd,
    /// LZ4 compression.
    Lz4,
    /// Snappy compression.
    Snappy,
    /// Brotli compression.
    Brotli,
}

impl Default for CompressionType {
    fn default() -> Self {
        Self::None
    }
}

impl CompressionType {
    /// Returns the file extension for this compression type.
    #[must_use]
    pub const fn extension(&self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Gzip => Some("gz"),
            Self::Zstd => Some("zst"),
            Self::Lz4 => Some("lz4"),
            Self::Snappy => Some("snappy"),
            Self::Brotli => Some("br"),
        }
    }
}

/// HATEOAS link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    /// Link URL.
    pub href: String,
    /// HTTP method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Whether the URL is templated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templated: Option<bool>,
    /// Link title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

impl Link {
    /// Creates a new link.
    #[must_use]
    pub fn new(href: impl Into<String>) -> Self {
        Self {
            href: href.into(),
            method: None,
            templated: None,
            title: None,
        }
    }

    /// Sets the HTTP method.
    #[must_use]
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Sets whether the URL is templated.
    #[must_use]
    pub fn templated(mut self, templated: bool) -> Self {
        self.templated = Some(templated);
        self
    }

    /// Sets the title.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
}

/// HATEOAS links collection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Links {
    /// Self link.
    #[serde(rename = "self")]
    pub self_link: Option<Link>,

    /// Additional links.
    #[serde(flatten)]
    pub links: HashMap<String, Link>,
}

impl Links {
    /// Creates new links with a self link.
    #[must_use]
    pub fn new(self_link: impl Into<String>) -> Self {
        Self {
            self_link: Some(Link::new(self_link)),
            links: HashMap::new(),
        }
    }

    /// Adds a link.
    pub fn add(&mut self, rel: impl Into<String>, link: Link) {
        self.links.insert(rel.into(), link);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata() {
        let mut meta = Metadata::empty();
        meta.set_str("key1", "value1");
        meta.set("key2", serde_json::json!(42));

        assert_eq!(meta.get_str("key1"), Some("value1"));
        assert_eq!(meta.get_i64("key2"), Some(42));
        assert!(meta.contains("key1"));
        assert_eq!(meta.len(), 2);
    }

    #[test]
    fn test_file_format() {
        assert_eq!(FileFormat::Json.mime_type(), "application/json");
        assert_eq!(FileFormat::Parquet.extension(), "parquet");
    }
}
