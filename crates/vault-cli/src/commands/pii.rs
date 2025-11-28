//! PII detection and anonymization commands.

use std::io::Read;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use colored::Colorize;

use vault_sdk::{PiiDetectionRequest, AnonymizationRequest, PiiType, AnonymizationStrategy};

use crate::output::{CliError, OutputFormat, success, info, print_output, TableDisplay};

use super::ClientConfig;

/// PII detection and anonymization commands.
#[derive(Args)]
pub struct PiiCommands {
    #[command(subcommand)]
    pub command: PiiSubcommand,
}

/// PII subcommands.
#[derive(Subcommand)]
pub enum PiiSubcommand {
    /// Detect PII in text
    Detect {
        /// Text to analyze
        #[arg(long, short, conflicts_with = "file")]
        text: Option<String>,

        /// Read from file
        #[arg(long, short, conflicts_with = "text")]
        file: Option<PathBuf>,

        /// Read from stdin
        #[arg(long, conflicts_with_all = ["text", "file"])]
        stdin: bool,

        /// Only detect specific PII types
        #[arg(long = "type", short = 't')]
        types: Vec<String>,

        /// Minimum confidence threshold (0.0-1.0)
        #[arg(long, default_value = "0.8")]
        min_confidence: f32,

        /// Include context around detections
        #[arg(long)]
        context: bool,
    },

    /// Anonymize text by replacing PII
    Anonymize {
        /// Text to anonymize
        #[arg(long, short, conflicts_with = "file")]
        text: Option<String>,

        /// Read from file
        #[arg(long, short, conflicts_with = "text")]
        file: Option<PathBuf>,

        /// Read from stdin
        #[arg(long, conflicts_with_all = ["text", "file"])]
        stdin: bool,

        /// Anonymization strategy
        #[arg(long, short, default_value = "redact")]
        strategy: AnonymizationStrategy,

        /// Only anonymize specific PII types
        #[arg(long = "type", short = 't')]
        types: Vec<String>,

        /// Minimum confidence threshold (0.0-1.0)
        #[arg(long, default_value = "0.8")]
        min_confidence: f32,

        /// Output only the anonymized text (no metadata)
        #[arg(long, short)]
        quiet: bool,
    },

    /// Check if text is clean (contains no PII)
    Check {
        /// Text to check
        #[arg(long, short, conflicts_with = "file")]
        text: Option<String>,

        /// Read from file
        #[arg(long, short, conflicts_with = "text")]
        file: Option<PathBuf>,

        /// Read from stdin
        #[arg(long, conflicts_with_all = ["text", "file"])]
        stdin: bool,

        /// Minimum confidence threshold
        #[arg(long, default_value = "0.8")]
        min_confidence: f32,
    },

    /// List supported PII types
    Types,

    /// List supported anonymization strategies
    Strategies,

    /// Interactive PII scanning mode
    Interactive,
}

impl PiiCommands {
    /// Runs the PII command.
    pub async fn run(self, config: &ClientConfig, format: OutputFormat) -> Result<(), CliError> {
        let client = config.build_client()?;

        match self.command {
            PiiSubcommand::Detect {
                text,
                file,
                stdin,
                types,
                min_confidence,
                context,
            } => {
                let input_text = Self::get_text(text, file, stdin)?;

                let pii_types: Vec<PiiType> = types
                    .iter()
                    .map(|t| t.parse())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| CliError::validation(e))?;

                let mut request = PiiDetectionRequest::new(&input_text)
                    .with_min_confidence(min_confidence);

                if !pii_types.is_empty() {
                    request = request.with_types(pii_types);
                }

                if context {
                    request = request.with_context();
                }

                let result = client.pii().detect_with_options(&request).await?;

                if result.entities.is_empty() {
                    success("No PII detected");
                } else {
                    print_output(&result, format)?;
                }
            }

            PiiSubcommand::Anonymize {
                text,
                file,
                stdin,
                strategy,
                types,
                min_confidence,
                quiet,
            } => {
                let input_text = Self::get_text(text, file, stdin)?;

                let pii_types: Vec<PiiType> = types
                    .iter()
                    .map(|t| t.parse())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| CliError::validation(e))?;

                let mut request = AnonymizationRequest::new(&input_text)
                    .with_strategy(strategy)
                    .with_min_confidence(min_confidence);

                if !pii_types.is_empty() {
                    request = request.with_types(pii_types);
                }

                let result = client.pii().anonymize_with_options(&request).await?;

                if quiet {
                    println!("{}", result.anonymized_text);
                } else {
                    print_output(&result, format)?;
                }
            }

            PiiSubcommand::Check {
                text,
                file,
                stdin,
                min_confidence,
            } => {
                let input_text = Self::get_text(text, file, stdin)?;

                let request = PiiDetectionRequest::new(&input_text)
                    .with_min_confidence(min_confidence);

                let result = client.pii().detect_with_options(&request).await?;

                if result.entities.is_empty() {
                    success("Text is clean - no PII detected");
                } else {
                    println!("{} {} PII entities detected:", "Warning:".yellow().bold(), result.entity_count);

                    for entity in &result.entities {
                        println!(
                            "  {} at position {}-{} (confidence: {:.2})",
                            entity.pii_type.to_string().yellow(),
                            entity.start,
                            entity.end,
                            entity.confidence,
                        );
                    }

                    return Err(CliError::validation("PII detected in text"));
                }
            }

            PiiSubcommand::Types => {
                let types = client.pii().supported_types().await?;

                println!("{}", "Supported PII Types:".bold().underline());
                println!();

                for t in types {
                    println!("{}", t.name.green().bold());
                    println!("  Type: {}", t.pii_type);
                    println!("  {}", t.description);
                    if !t.examples.is_empty() {
                        println!("  Examples: {}", t.examples.join(", "));
                    }
                    println!();
                }
            }

            PiiSubcommand::Strategies => {
                let strategies = client.pii().supported_strategies().await?;

                println!("{}", "Anonymization Strategies:".bold().underline());
                println!();

                for s in strategies {
                    println!("{}", s.name.green().bold());
                    println!("  Strategy: {}", s.strategy);
                    println!("  {}", s.description);
                    println!("  Example: {}", s.example);
                    println!();
                }
            }

            PiiSubcommand::Interactive => {
                use dialoguer::Input;

                println!("{}", "Interactive PII Scanner".bold().underline());
                println!("Enter text to scan for PII. Type 'exit' or 'quit' to stop.\n");

                loop {
                    let input: String = Input::new()
                        .with_prompt(">")
                        .interact_text()
                        .map_err(|e| CliError::io(format!("Failed to read input: {e}")))?;

                    let trimmed = input.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    if trimmed == "exit" || trimmed == "quit" {
                        break;
                    }

                    let result = client.pii().detect(trimmed).await?;

                    if result.entities.is_empty() {
                        println!("{} No PII detected\n", "✓".green());
                    } else {
                        println!(
                            "{} {} PII entities found:\n",
                            "!".yellow(),
                            result.entity_count
                        );

                        for entity in &result.entities {
                            // Highlight the PII in context
                            let before = &trimmed[..entity.start];
                            let pii = &trimmed[entity.start..entity.end];
                            let after = &trimmed[entity.end..];

                            println!(
                                "  {}: {}{}{} (confidence: {:.2})",
                                entity.pii_type.to_string().cyan(),
                                before,
                                pii.red().bold(),
                                after,
                                entity.confidence,
                            );
                        }
                        println!();
                    }
                }

                info("Exiting interactive mode");
            }
        }

        Ok(())
    }

    fn get_text(
        text: Option<String>,
        file: Option<PathBuf>,
        stdin: bool,
    ) -> Result<String, CliError> {
        if let Some(t) = text {
            Ok(t)
        } else if let Some(path) = file {
            std::fs::read_to_string(&path)
                .map_err(|e| CliError::io(format!("Failed to read file: {e}")))
        } else if stdin {
            let mut buffer = String::new();
            std::io::stdin()
                .read_to_string(&mut buffer)
                .map_err(|e| CliError::io(format!("Failed to read stdin: {e}")))?;
            Ok(buffer)
        } else {
            Err(CliError::validation(
                "Provide input with --text, --file, or --stdin"
            ))
        }
    }
}
