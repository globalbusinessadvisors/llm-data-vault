//! CLI configuration management.

use std::path::PathBuf;

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::output::{CliError, ErrorKind};

/// CLI configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Vault API URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// API key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// Bearer token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Default output format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_format: Option<String>,

    /// Request timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,

    /// Whether to use colors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<bool>,

    /// Default dataset ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_dataset: Option<String>,
}

impl Config {
    /// Returns the configuration directory.
    pub fn config_dir() -> Option<PathBuf> {
        ProjectDirs::from("com", "llm-data-vault", "vault-cli")
            .map(|dirs| dirs.config_dir().to_path_buf())
    }

    /// Returns the path to a profile's configuration file.
    pub fn profile_path(profile: &str) -> Option<PathBuf> {
        Self::config_dir().map(|dir| {
            if profile == "default" {
                dir.join("config.toml")
            } else {
                dir.join(format!("{profile}.toml"))
            }
        })
    }

    /// Loads configuration from a profile.
    pub fn load(profile: &str) -> Result<Self, CliError> {
        let path = Self::profile_path(profile)
            .ok_or_else(|| CliError::config("Could not determine config directory"))?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|e| CliError::with_cause(
                ErrorKind::Config,
                format!("Failed to read config file: {}", path.display()),
                e,
            ))?;

        toml::from_str(&content).map_err(|e| {
            CliError::with_cause(
                ErrorKind::Config,
                "Failed to parse configuration",
                e,
            )
        })
    }

    /// Saves configuration to a profile.
    pub fn save(&self, profile: &str) -> Result<(), CliError> {
        let path = Self::profile_path(profile)
            .ok_or_else(|| CliError::config("Could not determine config directory"))?;

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CliError::with_cause(
                    ErrorKind::Io,
                    "Failed to create config directory",
                    e,
                ))?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| CliError::with_cause(
                ErrorKind::Config,
                "Failed to serialize configuration",
                e,
            ))?;

        std::fs::write(&path, content)
            .map_err(|e| CliError::with_cause(
                ErrorKind::Io,
                format!("Failed to write config file: {}", path.display()),
                e,
            ))?;

        Ok(())
    }

    /// Lists available profiles.
    pub fn list_profiles() -> Result<Vec<String>, CliError> {
        let dir = Self::config_dir()
            .ok_or_else(|| CliError::config("Could not determine config directory"))?;

        if !dir.exists() {
            return Ok(vec!["default".to_string()]);
        }

        let mut profiles = Vec::new();

        for entry in std::fs::read_dir(&dir)
            .map_err(|e| CliError::with_cause(
                ErrorKind::Io,
                "Failed to read config directory",
                e,
            ))?
        {
            let entry = entry.map_err(|e| CliError::with_cause(
                ErrorKind::Io,
                "Failed to read directory entry",
                e,
            ))?;

            let path = entry.path();
            if path.extension().map(|e| e == "toml").unwrap_or(false) {
                if let Some(stem) = path.file_stem() {
                    let name = stem.to_string_lossy();
                    if name == "config" {
                        profiles.push("default".to_string());
                    } else {
                        profiles.push(name.to_string());
                    }
                }
            }
        }

        if profiles.is_empty() {
            profiles.push("default".to_string());
        }

        profiles.sort();
        Ok(profiles)
    }

    /// Sets a configuration value.
    pub fn set(&mut self, key: &str, value: &str) -> Result<(), CliError> {
        match key {
            "url" => self.url = Some(value.to_string()),
            "api_key" => self.api_key = Some(value.to_string()),
            "token" => self.token = Some(value.to_string()),
            "default_format" => self.default_format = Some(value.to_string()),
            "timeout" | "timeout_secs" => {
                self.timeout_secs = Some(value.parse().map_err(|_| {
                    CliError::validation(format!("Invalid timeout value: {value}"))
                })?);
            }
            "color" => {
                self.color = Some(value.parse().map_err(|_| {
                    CliError::validation(format!("Invalid boolean value: {value}"))
                })?);
            }
            "default_dataset" => self.default_dataset = Some(value.to_string()),
            _ => return Err(CliError::validation(format!("Unknown configuration key: {key}"))),
        }
        Ok(())
    }

    /// Gets a configuration value.
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "url" => self.url.clone(),
            "api_key" => self.api_key.as_ref().map(|_| "[REDACTED]".to_string()),
            "token" => self.token.as_ref().map(|_| "[REDACTED]".to_string()),
            "default_format" => self.default_format.clone(),
            "timeout" | "timeout_secs" => self.timeout_secs.map(|t| t.to_string()),
            "color" => self.color.map(|c| c.to_string()),
            "default_dataset" => self.default_dataset.clone(),
            _ => None,
        }
    }

    /// Removes a configuration value.
    pub fn unset(&mut self, key: &str) -> Result<(), CliError> {
        match key {
            "url" => self.url = None,
            "api_key" => self.api_key = None,
            "token" => self.token = None,
            "default_format" => self.default_format = None,
            "timeout" | "timeout_secs" => self.timeout_secs = None,
            "color" => self.color = None,
            "default_dataset" => self.default_dataset = None,
            _ => return Err(CliError::validation(format!("Unknown configuration key: {key}"))),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_set_get() {
        let mut config = Config::default();

        config.set("url", "https://api.example.com").unwrap();
        assert_eq!(config.url, Some("https://api.example.com".to_string()));

        config.set("timeout", "60").unwrap();
        assert_eq!(config.timeout_secs, Some(60));
    }

    #[test]
    fn test_config_invalid_key() {
        let mut config = Config::default();
        assert!(config.set("invalid_key", "value").is_err());
    }
}
