//! Output format options.

use std::str::FromStr;

use clap::ValueEnum;

/// Output format for CLI commands.
#[derive(Debug, Clone, Copy, Default, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable table format.
    #[default]
    Table,
    /// Pretty-printed JSON.
    Json,
    /// Compact JSON (single line).
    #[value(name = "json-compact")]
    JsonCompact,
    /// YAML format.
    Yaml,
    /// Plain text format (for scripting).
    Plain,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Table => write!(f, "table"),
            Self::Json => write!(f, "json"),
            Self::JsonCompact => write!(f, "json-compact"),
            Self::Yaml => write!(f, "yaml"),
            Self::Plain => write!(f, "plain"),
        }
    }
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(Self::Table),
            "json" => Ok(Self::Json),
            "json-compact" | "jsoncompact" => Ok(Self::JsonCompact),
            "yaml" | "yml" => Ok(Self::Yaml),
            "plain" | "text" => Ok(Self::Plain),
            _ => Err(format!("Unknown format: {s}. Use: table, json, json-compact, yaml, or plain")),
        }
    }
}
