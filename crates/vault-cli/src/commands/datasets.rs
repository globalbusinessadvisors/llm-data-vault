//! Dataset management commands.

use clap::{Args, Subcommand};
use colored::Colorize;

use vault_sdk::{DatasetCreate, DatasetUpdate, DatasetFormat, DatasetStatus};

use crate::output::{CliError, OutputFormat, success, info, print_output, print_list, TableDisplay};

use super::ClientConfig;

/// Dataset management commands.
#[derive(Args)]
pub struct DatasetsCommands {
    #[command(subcommand)]
    pub command: DatasetsSubcommand,
}

/// Dataset subcommands.
#[derive(Subcommand)]
pub enum DatasetsSubcommand {
    /// List all datasets
    #[command(alias = "ls")]
    List {
        /// Filter by status
        #[arg(long, short)]
        status: Option<DatasetStatus>,

        /// Filter by format
        #[arg(long)]
        format: Option<DatasetFormat>,

        /// Search by name
        #[arg(long, short)]
        search: Option<String>,

        /// Maximum number of results
        #[arg(long, default_value = "20")]
        limit: u32,

        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: u32,
    },

    /// Get dataset details
    Get {
        /// Dataset ID
        id: String,
    },

    /// Create a new dataset
    Create {
        /// Dataset name
        name: String,

        /// Dataset description
        #[arg(long, short)]
        description: Option<String>,

        /// Dataset format
        #[arg(long, short, default_value = "jsonl")]
        format: DatasetFormat,

        /// Labels (key=value)
        #[arg(long, short = 'l')]
        label: Vec<String>,
    },

    /// Update a dataset
    Update {
        /// Dataset ID
        id: String,

        /// New name
        #[arg(long)]
        name: Option<String>,

        /// New description
        #[arg(long)]
        description: Option<String>,
    },

    /// Delete a dataset
    #[command(alias = "rm")]
    Delete {
        /// Dataset ID
        id: String,

        /// Skip confirmation
        #[arg(long, short)]
        force: bool,
    },

    /// Get dataset statistics
    Stats {
        /// Dataset ID
        id: String,
    },

    /// Archive a dataset (make read-only)
    Archive {
        /// Dataset ID
        id: String,
    },

    /// Unarchive a dataset
    Unarchive {
        /// Dataset ID
        id: String,
    },

    /// Clone a dataset structure
    Clone {
        /// Source dataset ID
        id: String,

        /// Name for the cloned dataset
        #[arg(long)]
        name: String,
    },

    /// Trigger PII scan on all records
    Scan {
        /// Dataset ID
        id: String,
    },
}

impl DatasetsCommands {
    /// Runs the datasets command.
    pub async fn run(self, config: &ClientConfig, format: OutputFormat) -> Result<(), CliError> {
        let client = config.build_client()?;

        match self.command {
            DatasetsSubcommand::List {
                status,
                format: ds_format,
                search,
                limit,
                offset,
            } => {
                use vault_sdk::models::DatasetListParams;

                let mut params = DatasetListParams::new().with_pagination(limit, offset);

                if let Some(s) = status {
                    params = params.with_status(s);
                }
                if let Some(f) = ds_format {
                    params = params.with_format(f);
                }
                if let Some(s) = search {
                    params = params.with_search(s);
                }

                let datasets = client.datasets().list_with_params(&params).await?;

                if datasets.items.is_empty() {
                    info("No datasets found");
                } else {
                    print_list(&datasets.items, format)?;
                    if datasets.has_more {
                        info(&format!(
                            "Showing {} of {} datasets. Use --offset to see more.",
                            datasets.items.len(),
                            datasets.total
                        ));
                    }
                }
            }

            DatasetsSubcommand::Get { id } => {
                let dataset = client.datasets().get(&id).await?;
                print_output(&dataset, format)?;
            }

            DatasetsSubcommand::Create {
                name,
                description,
                format: ds_format,
                label,
            } => {
                let mut request = DatasetCreate::new(&name).with_format(ds_format);

                if let Some(desc) = description {
                    request = request.with_description(desc);
                }

                for l in label {
                    if let Some((key, value)) = l.split_once('=') {
                        request = request.with_label(key, value);
                    } else {
                        return Err(CliError::validation(
                            format!("Invalid label format: {l}. Use key=value")
                        ));
                    }
                }

                let dataset = client.datasets().create(&request).await?;
                success(&format!("Created dataset: {}", dataset.id));
                print_output(&dataset, format)?;
            }

            DatasetsSubcommand::Update { id, name, description } => {
                let mut request = DatasetUpdate::new();

                if let Some(n) = name {
                    request = request.with_name(n);
                }
                if let Some(d) = description {
                    request = request.with_description(d);
                }

                let dataset = client.datasets().update(&id, &request).await?;
                success("Dataset updated");
                print_output(&dataset, format)?;
            }

            DatasetsSubcommand::Delete { id, force } => {
                if !force {
                    use dialoguer::Confirm;

                    let confirmed = Confirm::new()
                        .with_prompt(format!(
                            "Delete dataset {} and ALL its records? This cannot be undone.",
                            id.yellow()
                        ))
                        .default(false)
                        .interact()
                        .map_err(|e| CliError::io(format!("Failed to read input: {e}")))?;

                    if !confirmed {
                        return Err(CliError::cancelled());
                    }
                }

                client.datasets().delete(&id).await?;
                success(&format!("Dataset {} deleted", id));
            }

            DatasetsSubcommand::Stats { id } => {
                let stats = client.datasets().stats(&id).await?;

                println!("{}: {}", "Records".bold(), stats.record_count);
                println!(
                    "{}: {}",
                    "Size".bold(),
                    crate::output::format_bytes(stats.size_bytes)
                );

                if let Some(ref pii) = stats.pii_stats {
                    println!("\n{}", "PII Statistics:".bold().underline());
                    println!("  Total entities: {}", pii.total_entities);
                    println!("  Records with PII: {}", pii.records_with_pii);

                    if !pii.by_type.is_empty() {
                        println!("\n  By type:");
                        for (pii_type, count) in &pii.by_type {
                            println!("    {}: {}", pii_type, count);
                        }
                    }
                }

                if let Some(ref scanned) = stats.last_scanned_at {
                    println!(
                        "\n{}: {}",
                        "Last Scanned".bold(),
                        scanned.format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }

            DatasetsSubcommand::Archive { id } => {
                let dataset = client.datasets().archive(&id).await?;
                success(&format!("Dataset {} archived", id));
                print_output(&dataset, format)?;
            }

            DatasetsSubcommand::Unarchive { id } => {
                let dataset = client.datasets().unarchive(&id).await?;
                success(&format!("Dataset {} unarchived", id));
                print_output(&dataset, format)?;
            }

            DatasetsSubcommand::Clone { id, name } => {
                let dataset = client.datasets().clone(&id, &name).await?;
                success(&format!("Cloned dataset as: {}", dataset.id));
                print_output(&dataset, format)?;
            }

            DatasetsSubcommand::Scan { id } => {
                client.datasets().scan_pii(&id).await?;
                success(&format!("PII scan initiated for dataset {}", id));
                info("Scan is running in the background. Use 'vault datasets stats' to check progress.");
            }
        }

        Ok(())
    }
}
