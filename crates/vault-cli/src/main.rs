//! LLM Data Vault CLI
//!
//! Enterprise command-line interface for managing LLM training data
//! with built-in PII detection and anonymization.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

mod commands;
mod config;
mod output;

use commands::Cli;

#[tokio::main]
async fn main() -> ExitCode {
    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn"));

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Run the command
    match cli.run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            output::print_error(&e);
            e.exit_code()
        }
    }
}
