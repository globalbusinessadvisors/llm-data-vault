//! Record management commands.

use std::io::Read;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use colored::Colorize;
use serde_json::Value;

use vault_sdk::{RecordCreate, RecordUpdate, RecordStatus, PiiScanStatus, RecordContent};

use crate::output::{CliError, OutputFormat, success, info, print_output, print_list, TableDisplay};

use super::ClientConfig;

/// Record management commands.
#[derive(Args)]
pub struct RecordsCommands {
    /// Dataset ID
    #[arg(long, short, env = "VAULT_DATASET")]
    dataset: String,

    #[command(subcommand)]
    pub command: RecordsSubcommand,
}

/// Record subcommands.
#[derive(Subcommand)]
pub enum RecordsSubcommand {
    /// List records in the dataset
    #[command(alias = "ls")]
    List {
        /// Filter by status
        #[arg(long, short)]
        status: Option<RecordStatus>,

        /// Filter by PII status
        #[arg(long)]
        pii_status: Option<PiiScanStatus>,

        /// Maximum number of results
        #[arg(long, default_value = "20")]
        limit: u32,

        /// Offset for pagination
        #[arg(long, default_value = "0")]
        offset: u32,
    },

    /// Get record details
    Get {
        /// Record ID
        id: String,

        /// Show content
        #[arg(long, short)]
        content: bool,
    },

    /// Create a new record
    Create {
        /// JSON content (or use --file)
        #[arg(long, short, conflicts_with = "file")]
        json: Option<String>,

        /// Read content from file
        #[arg(long, short, conflicts_with = "json")]
        file: Option<PathBuf>,

        /// Read from stdin
        #[arg(long, conflicts_with_all = ["json", "file"])]
        stdin: bool,

        /// Scan for PII
        #[arg(long, default_value = "true")]
        scan_pii: bool,

        /// Auto-anonymize detected PII
        #[arg(long)]
        auto_anonymize: bool,

        /// Labels (key=value)
        #[arg(long, short = 'l')]
        label: Vec<String>,
    },

    /// Create records from JSONL file
    Import {
        /// JSONL file to import
        file: PathBuf,

        /// Continue on error
        #[arg(long)]
        continue_on_error: bool,

        /// Scan for PII
        #[arg(long, default_value = "true")]
        scan_pii: bool,
    },

    /// Update a record
    Update {
        /// Record ID
        id: String,

        /// New status
        #[arg(long)]
        status: Option<RecordStatus>,
    },

    /// Delete a record
    #[command(alias = "rm")]
    Delete {
        /// Record ID
        id: String,

        /// Skip confirmation
        #[arg(long, short)]
        force: bool,
    },

    /// Get record count
    Count,

    /// Get PII results for a record
    Pii {
        /// Record ID
        id: String,
    },

    /// Trigger PII scan on a record
    Scan {
        /// Record ID
        id: String,
    },

    /// Get anonymized version of a record
    Anonymized {
        /// Record ID
        id: String,
    },

    /// Quarantine a record
    Quarantine {
        /// Record ID
        id: String,

        /// Reason for quarantine
        #[arg(long, short)]
        reason: String,
    },

    /// Release a record from quarantine
    Release {
        /// Record ID
        id: String,
    },
}

impl RecordsCommands {
    /// Runs the records command.
    pub async fn run(self, config: &ClientConfig, format: OutputFormat) -> Result<(), CliError> {
        let client = config.build_client()?;
        let records = client.records(&self.dataset);

        match self.command {
            RecordsSubcommand::List {
                status,
                pii_status,
                limit,
                offset,
            } => {
                use vault_sdk::models::RecordListParams;

                let mut params = RecordListParams::new().with_pagination(limit, offset);

                if let Some(s) = status {
                    params = params.with_status(s);
                }
                if let Some(p) = pii_status {
                    params = params.with_pii_status(p);
                }

                let record_list = records.list_with_params(&params).await?;

                if record_list.items.is_empty() {
                    info("No records found");
                } else {
                    print_list(&record_list.items, format)?;
                    if record_list.has_more {
                        info(&format!(
                            "Showing {} of {} records. Use --offset to see more.",
                            record_list.items.len(),
                            record_list.total
                        ));
                    }
                }
            }

            RecordsSubcommand::Get { id, content } => {
                let record = records.get(&id).await?;
                print_output(&record, format)?;

                if content {
                    println!("\n{}", "Content:".bold().underline());
                    match &record.content {
                        RecordContent::Json(v) => {
                            println!("{}", serde_json::to_string_pretty(v)?);
                        }
                        RecordContent::Text(t) => {
                            println!("{t}");
                        }
                        RecordContent::Binary(b) => {
                            println!("[Binary data: {} bytes]", b.len());
                        }
                        RecordContent::Reference { content_id, content_type } => {
                            println!("[Reference: {} ({})]", content_id, content_type);
                        }
                    }
                }
            }

            RecordsSubcommand::Create {
                json,
                file,
                stdin,
                scan_pii,
                auto_anonymize,
                label,
            } => {
                let content: Value = if let Some(json_str) = json {
                    serde_json::from_str(&json_str)?
                } else if let Some(path) = file {
                    let content = std::fs::read_to_string(&path)
                        .map_err(|e| CliError::io(format!("Failed to read file: {e}")))?;
                    serde_json::from_str(&content)?
                } else if stdin {
                    let mut buffer = String::new();
                    std::io::stdin().read_to_string(&mut buffer)
                        .map_err(|e| CliError::io(format!("Failed to read stdin: {e}")))?;
                    serde_json::from_str(&buffer)?
                } else {
                    return Err(CliError::validation(
                        "Provide content with --json, --file, or --stdin"
                    ));
                };

                let mut request = RecordCreate::json(content)
                    .with_pii_scan(scan_pii);

                if auto_anonymize {
                    request = request.with_auto_anonymize();
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

                let record = records.create(&request).await?;
                success(&format!("Created record: {}", record.id));
                print_output(&record, format)?;
            }

            RecordsSubcommand::Import {
                file,
                continue_on_error,
                scan_pii,
            } => {
                use vault_sdk::BulkRecordCreate;

                let content = std::fs::read_to_string(&file)
                    .map_err(|e| CliError::io(format!("Failed to read file: {e}")))?;

                let mut record_creates = Vec::new();

                for (i, line) in content.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }

                    let value: Value = serde_json::from_str(line)
                        .map_err(|e| CliError::validation(
                            format!("Invalid JSON on line {}: {e}", i + 1)
                        ))?;

                    record_creates.push(
                        RecordCreate::json(value).with_pii_scan(scan_pii)
                    );
                }

                if record_creates.is_empty() {
                    return Err(CliError::validation("No records to import"));
                }

                info(&format!("Importing {} records...", record_creates.len()));

                let bulk = BulkRecordCreate {
                    records: record_creates,
                    continue_on_error,
                };

                let result = records.create_bulk(&bulk).await?;

                success(&format!(
                    "Import complete: {} succeeded, {} failed",
                    result.succeeded, result.failed
                ));

                if result.failed > 0 {
                    println!("\n{}", "Failures:".yellow().bold());
                    for item in result.results.iter().filter(|r| !r.success) {
                        println!(
                            "  Line {}: {}",
                            item.index + 1,
                            item.error.as_deref().unwrap_or("Unknown error")
                        );
                    }
                }
            }

            RecordsSubcommand::Update { id, status } => {
                let mut request = RecordUpdate::new();

                if let Some(s) = status {
                    request = request.with_status(s);
                }

                let record = records.update(&id, &request).await?;
                success("Record updated");
                print_output(&record, format)?;
            }

            RecordsSubcommand::Delete { id, force } => {
                if !force {
                    use dialoguer::Confirm;

                    let confirmed = Confirm::new()
                        .with_prompt(format!("Delete record {}?", id.yellow()))
                        .default(false)
                        .interact()
                        .map_err(|e| CliError::io(format!("Failed to read input: {e}")))?;

                    if !confirmed {
                        return Err(CliError::cancelled());
                    }
                }

                records.delete(&id).await?;
                success(&format!("Record {} deleted", id));
            }

            RecordsSubcommand::Count => {
                let count = records.count().await?;
                println!("{count}");
            }

            RecordsSubcommand::Pii { id } => {
                let result = records.pii_results(&id).await?;
                print_output(&result, format)?;
            }

            RecordsSubcommand::Scan { id } => {
                let result = records.scan_pii(&id).await?;
                success(&format!("Scan complete: {} entities found", result.entity_count));
                print_output(&result, format)?;
            }

            RecordsSubcommand::Anonymized { id } => {
                let record = records.anonymized(&id).await?;
                print_output(&record, format)?;
            }

            RecordsSubcommand::Quarantine { id, reason } => {
                let record = records.quarantine(&id, &reason).await?;
                success(&format!("Record {} quarantined", id));
                print_output(&record, format)?;
            }

            RecordsSubcommand::Release { id } => {
                let record = records.release(&id).await?;
                success(&format!("Record {} released from quarantine", id));
                print_output(&record, format)?;
            }
        }

        Ok(())
    }
}
