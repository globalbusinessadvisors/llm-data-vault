//! API key management commands.

use clap::{Args, Subcommand};
use colored::Colorize;

use vault_sdk::ApiKeyCreate;

use crate::output::{CliError, OutputFormat, success, info, print_output, print_list, TableDisplay};

use super::ClientConfig;

/// API key management commands.
#[derive(Args)]
pub struct ApiKeysCommands {
    #[command(subcommand)]
    pub command: ApiKeysSubcommand,
}

/// API key subcommands.
#[derive(Subcommand)]
pub enum ApiKeysSubcommand {
    /// List all API keys
    #[command(alias = "ls")]
    List {
        /// Maximum number of results
        #[arg(long, default_value = "20")]
        limit: u32,

        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: u32,
    },

    /// Get API key details
    Get {
        /// API key ID
        id: String,
    },

    /// Create a new API key
    Create {
        /// Key name
        name: String,

        /// Permissions to grant
        #[arg(long, short)]
        permission: Vec<String>,

        /// Rate limit (requests per minute)
        #[arg(long)]
        rate_limit: Option<u32>,

        /// Allowed IP addresses
        #[arg(long)]
        allowed_ip: Vec<String>,
    },

    /// Revoke (delete) an API key
    Revoke {
        /// API key ID
        id: String,

        /// Skip confirmation
        #[arg(long, short)]
        force: bool,
    },

    /// Rotate an API key (generate new secret)
    Rotate {
        /// API key ID
        id: String,
    },

    /// Enable an API key
    Enable {
        /// API key ID
        id: String,
    },

    /// Disable an API key
    Disable {
        /// API key ID
        id: String,
    },
}

impl ApiKeysCommands {
    /// Runs the API keys command.
    pub async fn run(self, config: &ClientConfig, format: OutputFormat) -> Result<(), CliError> {
        let client = config.build_client()?;

        match self.command {
            ApiKeysSubcommand::List { limit, offset } => {
                use vault_sdk::Pagination;

                let pagination = Pagination::new(limit, offset);
                let keys = client.api_keys().list_with_pagination(&pagination).await?;

                if keys.items.is_empty() {
                    info("No API keys found");
                } else {
                    print_list(&keys.items, format)?;
                    if keys.has_more {
                        info(&format!(
                            "Showing {} of {} keys. Use --offset to see more.",
                            keys.items.len(),
                            keys.total
                        ));
                    }
                }
            }

            ApiKeysSubcommand::Get { id } => {
                let key = client.api_keys().get(&id).await?;
                print_output(&key, format)?;
            }

            ApiKeysSubcommand::Create {
                name,
                permission,
                rate_limit,
                allowed_ip,
            } => {
                if permission.is_empty() {
                    return Err(CliError::validation(
                        "At least one permission is required. Use --permission"
                    ));
                }

                let mut request = ApiKeyCreate::new(&name, permission);

                if let Some(limit) = rate_limit {
                    request = request.with_rate_limit(limit);
                }

                if !allowed_ip.is_empty() {
                    request = request.with_allowed_ips(allowed_ip);
                }

                let response = client.api_keys().create(&request).await?;

                success(&format!("Created API key: {}", response.api_key.id));

                println!(
                    "\n{} {}",
                    "Secret (save this - it won't be shown again):".yellow().bold(),
                    ""
                );
                println!("{}", response.secret);

                println!("\n{}", "Key details:".bold());
                print_output(&response.api_key, format)?;
            }

            ApiKeysSubcommand::Revoke { id, force } => {
                if !force {
                    use dialoguer::Confirm;

                    let confirmed = Confirm::new()
                        .with_prompt(format!(
                            "Revoke API key {}? This cannot be undone.",
                            id.yellow()
                        ))
                        .default(false)
                        .interact()
                        .map_err(|e| CliError::io(format!("Failed to read input: {e}")))?;

                    if !confirmed {
                        return Err(CliError::cancelled());
                    }
                }

                client.api_keys().revoke(&id).await?;
                success(&format!("API key {} revoked", id));
            }

            ApiKeysSubcommand::Rotate { id } => {
                let response = client.api_keys().rotate(&id).await?;

                success(&format!("API key {} rotated", id));

                println!(
                    "\n{} {}",
                    "New secret (save this - it won't be shown again):".yellow().bold(),
                    ""
                );
                println!("{}", response.secret);
            }

            ApiKeysSubcommand::Enable { id } => {
                let key = client.api_keys().enable(&id).await?;
                success(&format!("API key {} enabled", id));
                print_output(&key, format)?;
            }

            ApiKeysSubcommand::Disable { id } => {
                let key = client.api_keys().disable(&id).await?;
                success(&format!("API key {} disabled", id));
                print_output(&key, format)?;
            }
        }

        Ok(())
    }
}
