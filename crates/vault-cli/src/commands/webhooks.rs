//! Webhook management commands.

use clap::{Args, Subcommand};
use colored::Colorize;

use vault_sdk::{WebhookCreate, WebhookUpdate, WebhookEvent};

use crate::output::{CliError, OutputFormat, success, info, print_output, print_list, TableDisplay};

use super::ClientConfig;

/// Webhook management commands.
#[derive(Args)]
pub struct WebhooksCommands {
    #[command(subcommand)]
    pub command: WebhooksSubcommand,
}

/// Webhook subcommands.
#[derive(Subcommand)]
pub enum WebhooksSubcommand {
    /// List all webhooks
    #[command(alias = "ls")]
    List {
        /// Maximum number of results
        #[arg(long, default_value = "20")]
        limit: u32,

        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: u32,
    },

    /// Get webhook details
    Get {
        /// Webhook ID
        id: String,
    },

    /// Create a new webhook
    Create {
        /// Webhook name
        name: String,

        /// Webhook URL
        url: String,

        /// Events to subscribe to
        #[arg(long, short)]
        event: Vec<String>,

        /// Webhook secret
        #[arg(long, short)]
        secret: Option<String>,
    },

    /// Update a webhook
    Update {
        /// Webhook ID
        id: String,

        /// New name
        #[arg(long)]
        name: Option<String>,

        /// New URL
        #[arg(long)]
        url: Option<String>,

        /// New events (replaces existing)
        #[arg(long)]
        events: Option<Vec<String>>,
    },

    /// Delete a webhook
    #[command(alias = "rm")]
    Delete {
        /// Webhook ID
        id: String,

        /// Skip confirmation
        #[arg(long, short)]
        force: bool,
    },

    /// Enable a webhook
    Enable {
        /// Webhook ID
        id: String,
    },

    /// Disable a webhook
    Disable {
        /// Webhook ID
        id: String,
    },

    /// Rotate webhook secret
    RotateSecret {
        /// Webhook ID
        id: String,
    },

    /// Send a test delivery
    Test {
        /// Webhook ID
        id: String,
    },

    /// List deliveries for a webhook
    Deliveries {
        /// Webhook ID
        id: String,

        /// Maximum number of results
        #[arg(long, default_value = "20")]
        limit: u32,

        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: u32,
    },

    /// Retry a failed delivery
    Retry {
        /// Webhook ID
        webhook_id: String,

        /// Delivery ID
        delivery_id: String,
    },

    /// List available webhook events
    Events,
}

impl WebhooksCommands {
    /// Runs the webhooks command.
    pub async fn run(self, config: &ClientConfig, format: OutputFormat) -> Result<(), CliError> {
        let client = config.build_client()?;

        match self.command {
            WebhooksSubcommand::List { limit, offset } => {
                use vault_sdk::Pagination;

                let pagination = Pagination::new(limit, offset);
                let webhooks = client.webhooks().list_with_pagination(&pagination).await?;

                if webhooks.items.is_empty() {
                    info("No webhooks found");
                } else {
                    print_list(&webhooks.items, format)?;
                    if webhooks.has_more {
                        info(&format!(
                            "Showing {} of {} webhooks. Use --offset to see more.",
                            webhooks.items.len(),
                            webhooks.total
                        ));
                    }
                }
            }

            WebhooksSubcommand::Get { id } => {
                let webhook = client.webhooks().get(&id).await?;
                print_output(&webhook, format)?;
            }

            WebhooksSubcommand::Create { name, url, event, secret } => {
                if event.is_empty() {
                    return Err(CliError::validation(
                        "At least one event is required. Use --event"
                    ));
                }

                let events: Vec<WebhookEvent> = event
                    .iter()
                    .map(|e| Self::parse_event(e))
                    .collect::<Result<Vec<_>, _>>()?;

                let mut request = WebhookCreate::new(&name, &url, events);

                if let Some(s) = secret {
                    request = request.with_secret(s);
                }

                let webhook = client.webhooks().create(&request).await?;
                success(&format!("Created webhook: {}", webhook.id));
                print_output(&webhook, format)?;
            }

            WebhooksSubcommand::Update { id, name, url, events } => {
                let mut request = WebhookUpdate::new();

                if let Some(n) = name {
                    request = request.with_name(n);
                }
                if let Some(u) = url {
                    request = request.with_url(u);
                }
                if let Some(e) = events {
                    let parsed: Vec<WebhookEvent> = e
                        .iter()
                        .map(|ev| Self::parse_event(ev))
                        .collect::<Result<Vec<_>, _>>()?;
                    request = request.with_events(parsed);
                }

                let webhook = client.webhooks().update(&id, &request).await?;
                success("Webhook updated");
                print_output(&webhook, format)?;
            }

            WebhooksSubcommand::Delete { id, force } => {
                if !force {
                    use dialoguer::Confirm;

                    let confirmed = Confirm::new()
                        .with_prompt(format!("Delete webhook {}?", id.yellow()))
                        .default(false)
                        .interact()
                        .map_err(|e| CliError::io(format!("Failed to read input: {e}")))?;

                    if !confirmed {
                        return Err(CliError::cancelled());
                    }
                }

                client.webhooks().delete(&id).await?;
                success(&format!("Webhook {} deleted", id));
            }

            WebhooksSubcommand::Enable { id } => {
                let webhook = client.webhooks().enable(&id).await?;
                success(&format!("Webhook {} enabled", id));
                print_output(&webhook, format)?;
            }

            WebhooksSubcommand::Disable { id } => {
                let webhook = client.webhooks().disable(&id).await?;
                success(&format!("Webhook {} disabled", id));
                print_output(&webhook, format)?;
            }

            WebhooksSubcommand::RotateSecret { id } => {
                let response = client.webhooks().rotate_secret(&id).await?;

                success("Secret rotated successfully");
                println!("\n{}", "New secret (save this - it won't be shown again):".yellow().bold());
                println!("{}", response.secret);
                println!(
                    "\nNew secret active at: {}",
                    response.active_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!(
                    "Old secret expires at: {}",
                    response.old_secret_expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }

            WebhooksSubcommand::Test { id } => {
                let delivery = client.webhooks().test(&id).await?;

                match delivery.status {
                    vault_sdk::DeliveryStatus::Delivered => {
                        success(&format!(
                            "Test delivery successful! HTTP {} in {}ms",
                            delivery.http_status.unwrap_or(0),
                            delivery.response_time_ms.unwrap_or(0)
                        ));
                    }
                    vault_sdk::DeliveryStatus::Failed => {
                        println!(
                            "{} Test delivery failed: {}",
                            "✗".red().bold(),
                            delivery.error.as_deref().unwrap_or("Unknown error")
                        );
                    }
                    _ => {
                        info(&format!("Delivery status: {}", delivery.status));
                    }
                }
            }

            WebhooksSubcommand::Deliveries { id, limit, offset } => {
                use vault_sdk::Pagination;

                let pagination = Pagination::new(limit, offset);
                let deliveries = client
                    .webhooks()
                    .deliveries_with_pagination(&id, &pagination)
                    .await?;

                if deliveries.items.is_empty() {
                    info("No deliveries found");
                } else {
                    println!("ID\tSTATUS\tHTTP\tTIME\tCREATED");
                    println!("{}", "-".repeat(70));

                    for d in &deliveries.items {
                        let status_str = match d.status {
                            vault_sdk::DeliveryStatus::Delivered => "delivered".green(),
                            vault_sdk::DeliveryStatus::Failed => "failed".red(),
                            vault_sdk::DeliveryStatus::Retrying => "retrying".yellow(),
                            vault_sdk::DeliveryStatus::Pending => "pending".blue(),
                            vault_sdk::DeliveryStatus::InProgress => "in_progress".cyan(),
                        };

                        println!(
                            "{}\t{}\t{}\t{}ms\t{}",
                            d.id,
                            status_str,
                            d.http_status.map(|s| s.to_string()).unwrap_or("-".to_string()),
                            d.response_time_ms.unwrap_or(0),
                            d.created_at.format("%Y-%m-%d %H:%M"),
                        );
                    }

                    if deliveries.has_more {
                        info(&format!(
                            "\nShowing {} of {} deliveries.",
                            deliveries.items.len(),
                            deliveries.total
                        ));
                    }
                }
            }

            WebhooksSubcommand::Retry { webhook_id, delivery_id } => {
                let delivery = client
                    .webhooks()
                    .retry_delivery(&webhook_id, &delivery_id)
                    .await?;

                success(&format!("Retry initiated. Status: {}", delivery.status));
            }

            WebhooksSubcommand::Events => {
                let events = client.webhooks().available_events().await?;

                println!("{}", "Available Webhook Events:".bold().underline());
                println!();

                for e in events {
                    println!("{}", e.name.green().bold());
                    println!("  Event: {}", e.event);
                    println!("  {}", e.description);
                    println!();
                }
            }
        }

        Ok(())
    }

    fn parse_event(s: &str) -> Result<WebhookEvent, CliError> {
        match s.to_lowercase().as_str() {
            "dataset.created" => Ok(WebhookEvent::DatasetCreated),
            "dataset.updated" => Ok(WebhookEvent::DatasetUpdated),
            "dataset.deleted" => Ok(WebhookEvent::DatasetDeleted),
            "record.created" => Ok(WebhookEvent::RecordCreated),
            "record.updated" => Ok(WebhookEvent::RecordUpdated),
            "record.deleted" => Ok(WebhookEvent::RecordDeleted),
            "pii.detected" => Ok(WebhookEvent::PiiDetected),
            "record.quarantined" => Ok(WebhookEvent::RecordQuarantined),
            "import.completed" => Ok(WebhookEvent::ImportCompleted),
            "export.completed" => Ok(WebhookEvent::ExportCompleted),
            _ => Err(CliError::validation(format!("Unknown event: {s}"))),
        }
    }
}
