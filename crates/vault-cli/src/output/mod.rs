//! Output formatting and display utilities.

mod error;
mod format;
mod table;

pub use error::{CliError, ErrorKind, print_error};
pub use format::OutputFormat;
pub use table::{TableBuilder, TableDisplay};

use colored::Colorize;
use serde::Serialize;

/// Prints a success message.
pub fn success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Prints an info message.
pub fn info(message: &str) {
    println!("{} {}", "ℹ".blue().bold(), message);
}

/// Prints a warning message.
pub fn warn(message: &str) {
    eprintln!("{} {}", "⚠".yellow().bold(), message);
}

/// Prints formatted output based on the selected format.
pub fn print_output<T: Serialize + TableDisplay>(data: &T, format: OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Table => {
            data.print_table();
            Ok(())
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(data)
                .map_err(|e| CliError::output(format!("Failed to serialize JSON: {e}")))?;
            println!("{json}");
            Ok(())
        }
        OutputFormat::JsonCompact => {
            let json = serde_json::to_string(data)
                .map_err(|e| CliError::output(format!("Failed to serialize JSON: {e}")))?;
            println!("{json}");
            Ok(())
        }
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(data)
                .map_err(|e| CliError::output(format!("Failed to serialize YAML: {e}")))?;
            print!("{yaml}");
            Ok(())
        }
        OutputFormat::Plain => {
            data.print_plain();
            Ok(())
        }
    }
}

/// Prints a list of items.
pub fn print_list<T: Serialize + TableDisplay>(items: &[T], format: OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Table => {
            T::print_table_header();
            for item in items {
                item.print_table_row();
            }
            Ok(())
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(items)
                .map_err(|e| CliError::output(format!("Failed to serialize JSON: {e}")))?;
            println!("{json}");
            Ok(())
        }
        OutputFormat::JsonCompact => {
            let json = serde_json::to_string(items)
                .map_err(|e| CliError::output(format!("Failed to serialize JSON: {e}")))?;
            println!("{json}");
            Ok(())
        }
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(items)
                .map_err(|e| CliError::output(format!("Failed to serialize YAML: {e}")))?;
            print!("{yaml}");
            Ok(())
        }
        OutputFormat::Plain => {
            for item in items {
                item.print_plain();
            }
            Ok(())
        }
    }
}

/// Formats a byte size for human-readable display.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Formats a duration for human-readable display.
pub fn format_duration(secs: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = MINUTE * 60;
    const DAY: u64 = HOUR * 24;

    if secs >= DAY {
        let days = secs / DAY;
        let hours = (secs % DAY) / HOUR;
        if hours > 0 {
            format!("{}d {}h", days, hours)
        } else {
            format!("{}d", days)
        }
    } else if secs >= HOUR {
        let hours = secs / HOUR;
        let mins = (secs % HOUR) / MINUTE;
        if mins > 0 {
            format!("{}h {}m", hours, mins)
        } else {
            format!("{}h", hours)
        }
    } else if secs >= MINUTE {
        let mins = secs / MINUTE;
        let secs_rem = secs % MINUTE;
        if secs_rem > 0 {
            format!("{}m {}s", mins, secs_rem)
        } else {
            format!("{}m", mins)
        }
    } else {
        format!("{}s", secs)
    }
}

/// Truncates a string to a maximum length with ellipsis.
pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else if max_len <= 3 {
        s.chars().take(max_len).collect()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
