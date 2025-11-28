//! Configuration management commands.

use clap::{Args, Subcommand};
use colored::Colorize;

use crate::config::Config;
use crate::output::{CliError, OutputFormat, success, info};

/// Configuration management commands.
#[derive(Args)]
pub struct ConfigCommands {
    #[command(subcommand)]
    pub command: ConfigSubcommand,
}

/// Configuration subcommands.
#[derive(Subcommand)]
pub enum ConfigSubcommand {
    /// Show current configuration
    Show {
        /// Profile to show (default: current)
        #[arg(long, short)]
        profile: Option<String>,

        /// Show configuration file path
        #[arg(long)]
        path: bool,
    },

    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,

        /// Configuration value
        value: String,

        /// Profile to update (default: default)
        #[arg(long, short)]
        profile: Option<String>,
    },

    /// Get a configuration value
    Get {
        /// Configuration key
        key: String,

        /// Profile to read (default: default)
        #[arg(long, short)]
        profile: Option<String>,
    },

    /// Remove a configuration value
    Unset {
        /// Configuration key
        key: String,

        /// Profile to update (default: default)
        #[arg(long, short)]
        profile: Option<String>,
    },

    /// List available profiles
    Profiles,

    /// Initialize a new profile
    Init {
        /// Profile name
        #[arg(default_value = "default")]
        name: String,

        /// Vault API URL
        #[arg(long)]
        url: Option<String>,

        /// API key
        #[arg(long)]
        api_key: Option<String>,

        /// Force overwrite existing profile
        #[arg(long, short)]
        force: bool,
    },

    /// Show configuration file location
    Path,
}

impl ConfigCommands {
    /// Runs the config command.
    pub async fn run(self, format: OutputFormat) -> Result<(), CliError> {
        match self.command {
            ConfigSubcommand::Show { profile, path } => {
                let profile_name = profile.as_deref().unwrap_or("default");

                if path {
                    if let Some(p) = Config::profile_path(profile_name) {
                        println!("{}", p.display());
                    } else {
                        return Err(CliError::config("Could not determine config path"));
                    }
                    return Ok(());
                }

                let config = Config::load(profile_name)?;

                println!("{}", format!("Configuration (profile: {})", profile_name).bold().underline());
                println!();

                let show_value = |key: &str, value: Option<&String>, redact: bool| {
                    match value {
                        Some(v) if redact => {
                            println!("{}: {}", key.cyan(), "[REDACTED]".dimmed());
                        }
                        Some(v) => {
                            println!("{}: {}", key.cyan(), v);
                        }
                        None => {
                            println!("{}: {}", key.cyan(), "(not set)".dimmed());
                        }
                    }
                };

                show_value("url", config.url.as_ref(), false);
                show_value("api_key", config.api_key.as_ref(), true);
                show_value("token", config.token.as_ref(), true);
                show_value("default_format", config.default_format.as_ref(), false);
                show_value(
                    "timeout_secs",
                    config.timeout_secs.map(|t| t.to_string()).as_ref(),
                    false,
                );
                show_value(
                    "color",
                    config.color.map(|c| c.to_string()).as_ref(),
                    false,
                );
                show_value("default_dataset", config.default_dataset.as_ref(), false);
            }

            ConfigSubcommand::Set { key, value, profile } => {
                let profile_name = profile.as_deref().unwrap_or("default");

                let mut config = Config::load(profile_name)?;
                config.set(&key, &value)?;
                config.save(profile_name)?;

                success(&format!("Set {} = {}", key, if key.contains("key") || key.contains("token") { "[REDACTED]" } else { &value }));
            }

            ConfigSubcommand::Get { key, profile } => {
                let profile_name = profile.as_deref().unwrap_or("default");
                let config = Config::load(profile_name)?;

                match config.get(&key) {
                    Some(value) => println!("{value}"),
                    None => {
                        return Err(CliError::config(format!("Key '{}' is not set", key)));
                    }
                }
            }

            ConfigSubcommand::Unset { key, profile } => {
                let profile_name = profile.as_deref().unwrap_or("default");

                let mut config = Config::load(profile_name)?;
                config.unset(&key)?;
                config.save(profile_name)?;

                success(&format!("Unset {}", key));
            }

            ConfigSubcommand::Profiles => {
                let profiles = Config::list_profiles()?;

                println!("{}", "Available profiles:".bold().underline());
                for profile in profiles {
                    println!("  {}", profile);
                }
            }

            ConfigSubcommand::Init { name, url, api_key, force } => {
                let path = Config::profile_path(&name)
                    .ok_or_else(|| CliError::config("Could not determine config path"))?;

                if path.exists() && !force {
                    return Err(CliError::config(format!(
                        "Profile '{}' already exists. Use --force to overwrite.",
                        name
                    )));
                }

                let mut config = Config::default();

                if let Some(u) = url {
                    config.url = Some(u);
                } else {
                    use dialoguer::Input;

                    let url: String = Input::new()
                        .with_prompt("Vault API URL")
                        .default("http://localhost:8080".to_string())
                        .interact_text()
                        .map_err(|e| CliError::io(format!("Failed to read input: {e}")))?;

                    config.url = Some(url);
                }

                if let Some(k) = api_key {
                    config.api_key = Some(k);
                } else {
                    use dialoguer::Input;

                    let key: String = Input::new()
                        .with_prompt("API key (leave empty to skip)")
                        .allow_empty(true)
                        .interact_text()
                        .map_err(|e| CliError::io(format!("Failed to read input: {e}")))?;

                    if !key.is_empty() {
                        config.api_key = Some(key);
                    }
                }

                config.save(&name)?;

                success(&format!("Profile '{}' created at {}", name, path.display()));
            }

            ConfigSubcommand::Path => {
                if let Some(dir) = Config::config_dir() {
                    println!("{}", dir.display());
                } else {
                    return Err(CliError::config("Could not determine config directory"));
                }
            }
        }

        Ok(())
    }
}
