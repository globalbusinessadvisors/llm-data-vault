//! Table formatting utilities.

use tabled::{Table, Tabled, settings::Style};

/// Trait for types that can be displayed as a table.
pub trait TableDisplay: serde::Serialize {
    /// Prints as a formatted table.
    fn print_table(&self);

    /// Prints a single row (for list iteration).
    fn print_table_row(&self);

    /// Prints the table header (for list iteration).
    fn print_table_header() {}

    /// Prints as plain text.
    fn print_plain(&self);
}

/// Builder for creating custom tables.
pub struct TableBuilder {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl TableBuilder {
    /// Creates a new table builder.
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
            rows: Vec::new(),
        }
    }

    /// Sets the headers.
    pub fn headers(mut self, headers: Vec<&str>) -> Self {
        self.headers = headers.into_iter().map(String::from).collect();
        self
    }

    /// Adds a row.
    pub fn row(mut self, row: Vec<String>) -> Self {
        self.rows.push(row);
        self
    }

    /// Adds multiple rows.
    pub fn rows(mut self, rows: Vec<Vec<String>>) -> Self {
        self.rows.extend(rows);
        self
    }

    /// Prints the table.
    pub fn print(&self) {
        if self.rows.is_empty() {
            println!("No data to display.");
            return;
        }

        // Create a simple table representation
        #[derive(Tabled)]
        struct Row {
            #[tabled(skip)]
            values: Vec<String>,
        }

        // Print headers
        if !self.headers.is_empty() {
            println!("{}", self.headers.join("\t"));
            println!("{}", "-".repeat(60));
        }

        // Print rows
        for row in &self.rows {
            println!("{}", row.join("\t"));
        }
    }
}

impl Default for TableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Macro for implementing TableDisplay for simple types.
#[macro_export]
macro_rules! impl_table_display {
    ($type:ty, $fields:expr, $headers:expr) => {
        impl $crate::output::TableDisplay for $type {
            fn print_table(&self) {
                let builder = $crate::output::TableBuilder::new()
                    .headers($headers)
                    .row($fields(self));
                builder.print();
            }

            fn print_table_row(&self) {
                println!("{}", $fields(self).join("\t"));
            }

            fn print_table_header() {
                println!("{}", $headers.join("\t"));
                println!("{}", "-".repeat(60));
            }

            fn print_plain(&self) {
                let fields = $fields(self);
                let headers = $headers;
                for (h, v) in headers.iter().zip(fields.iter()) {
                    println!("{}: {}", h, v);
                }
            }
        }
    };
}

// Implement TableDisplay for common SDK types

impl TableDisplay for vault_sdk::Dataset {
    fn print_table(&self) {
        use colored::Colorize;

        println!("{}: {}", "ID".bold(), self.id);
        println!("{}: {}", "Name".bold(), self.name);
        if let Some(ref desc) = self.description {
            println!("{}: {}", "Description".bold(), desc);
        }
        println!("{}: {}", "Format".bold(), self.format);
        println!("{}: {}", "Status".bold(), format_status(&self.status.to_string()));
        println!("{}: {}", "Records".bold(), self.record_count);
        println!("{}: {}", "Size".bold(), crate::output::format_bytes(self.size_bytes));
        println!("{}: {}", "Created".bold(), self.created_at.format("%Y-%m-%d %H:%M:%S"));
        println!("{}: {}", "Updated".bold(), self.updated_at.format("%Y-%m-%d %H:%M:%S"));

        if !self.labels.is_empty() {
            println!("{}: {:?}", "Labels".bold(), self.labels);
        }
    }

    fn print_table_row(&self) {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.id,
            crate::output::truncate(&self.name, 30),
            self.format,
            self.status,
            self.record_count,
            crate::output::format_bytes(self.size_bytes),
        );
    }

    fn print_table_header() {
        println!("ID\tNAME\tFORMAT\tSTATUS\tRECORDS\tSIZE");
        println!("{}", "-".repeat(80));
    }

    fn print_plain(&self) {
        println!("{}", self.id);
    }
}

impl TableDisplay for vault_sdk::Record {
    fn print_table(&self) {
        use colored::Colorize;

        println!("{}: {}", "ID".bold(), self.id);
        println!("{}: {}", "Dataset ID".bold(), self.dataset_id);
        println!("{}: {}", "Status".bold(), format_status(&self.status.to_string()));
        println!("{}: {}", "PII Status".bold(), format_pii_status(&self.pii_status.to_string()));
        println!("{}: {}", "PII Count".bold(), self.pii_count);
        println!("{}: {}", "Size".bold(), crate::output::format_bytes(self.size_bytes));
        println!("{}: {}", "Content Hash".bold(), &self.content_hash[..16]);
        println!("{}: {}", "Version".bold(), self.version);
        println!("{}: {}", "Created".bold(), self.created_at.format("%Y-%m-%d %H:%M:%S"));

        if !self.labels.is_empty() {
            println!("{}: {:?}", "Labels".bold(), self.labels);
        }
    }

    fn print_table_row(&self) {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            self.id,
            self.status,
            self.pii_status,
            self.pii_count,
            crate::output::format_bytes(self.size_bytes),
        );
    }

    fn print_table_header() {
        println!("ID\tSTATUS\tPII_STATUS\tPII_COUNT\tSIZE");
        println!("{}", "-".repeat(70));
    }

    fn print_plain(&self) {
        println!("{}", self.id);
    }
}

impl TableDisplay for vault_sdk::Webhook {
    fn print_table(&self) {
        use colored::Colorize;

        println!("{}: {}", "ID".bold(), self.id);
        println!("{}: {}", "Name".bold(), self.name);
        println!("{}: {}", "URL".bold(), self.url);
        println!("{}: {}", "Active".bold(), if self.active { "Yes".green() } else { "No".red() });
        println!("{}: {:?}", "Events".bold(), self.events);
        println!("{}: {}", "Created".bold(), self.created_at.format("%Y-%m-%d %H:%M:%S"));

        if let Some(ref last) = self.last_delivery_at {
            println!("{}: {}", "Last Delivery".bold(), last.format("%Y-%m-%d %H:%M:%S"));
        }
    }

    fn print_table_row(&self) {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            self.id,
            crate::output::truncate(&self.name, 20),
            crate::output::truncate(&self.url, 40),
            if self.active { "active" } else { "inactive" },
            self.events.len(),
        );
    }

    fn print_table_header() {
        println!("ID\tNAME\tURL\tSTATUS\tEVENTS");
        println!("{}", "-".repeat(100));
    }

    fn print_plain(&self) {
        println!("{}", self.id);
    }
}

impl TableDisplay for vault_sdk::ApiKey {
    fn print_table(&self) {
        use colored::Colorize;

        println!("{}: {}", "ID".bold(), self.id);
        println!("{}: {}", "Name".bold(), self.name);
        println!("{}: {}", "Prefix".bold(), self.prefix);
        println!("{}: {}", "Active".bold(), if self.active { "Yes".green() } else { "No".red() });
        println!("{}: {:?}", "Permissions".bold(), self.permissions);
        println!("{}: {}", "Created".bold(), self.created_at.format("%Y-%m-%d %H:%M:%S"));

        if let Some(ref last) = self.last_used_at {
            println!("{}: {}", "Last Used".bold(), last.format("%Y-%m-%d %H:%M:%S"));
        }
        if let Some(ref exp) = self.expires_at {
            println!("{}: {}", "Expires".bold(), exp.format("%Y-%m-%d %H:%M:%S"));
        }
    }

    fn print_table_row(&self) {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            self.id,
            crate::output::truncate(&self.name, 20),
            self.prefix,
            if self.active { "active" } else { "inactive" },
            self.permissions.len(),
        );
    }

    fn print_table_header() {
        println!("ID\tNAME\tPREFIX\tSTATUS\tPERMISSIONS");
        println!("{}", "-".repeat(80));
    }

    fn print_plain(&self) {
        println!("{}", self.id);
    }
}

impl TableDisplay for vault_sdk::PiiDetectionResult {
    fn print_table(&self) {
        use colored::Colorize;

        println!("{}: {}", "ID".bold(), self.id);
        println!("{}: {}", "Entities Found".bold(), self.entity_count);
        println!("{}: {}ms", "Processing Time".bold(), self.processing_time_ms);
        println!("{}: {}", "Detected At".bold(), self.detected_at.format("%Y-%m-%d %H:%M:%S"));

        if !self.entities.is_empty() {
            println!("\n{}", "Entities:".bold().underline());
            for entity in &self.entities {
                println!(
                    "  {} at {}-{}: {} (confidence: {:.2})",
                    entity.pii_type.to_string().yellow(),
                    entity.start,
                    entity.end,
                    entity.text,
                    entity.confidence,
                );
            }
        }
    }

    fn print_table_row(&self) {
        println!(
            "{}\t{}\t{}ms",
            self.id,
            self.entity_count,
            self.processing_time_ms,
        );
    }

    fn print_table_header() {
        println!("ID\tENTITIES\tTIME");
        println!("{}", "-".repeat(50));
    }

    fn print_plain(&self) {
        for entity in &self.entities {
            println!("{}\t{}\t{}", entity.pii_type, entity.start, entity.end);
        }
    }
}

impl TableDisplay for vault_sdk::AnonymizationResult {
    fn print_table(&self) {
        use colored::Colorize;

        println!("{}", "Anonymized Text:".bold().underline());
        println!("{}", self.anonymized_text);
        println!();
        println!("{}: {}", "Entities Anonymized".bold(), self.entity_count);
        println!("{}: {}ms", "Processing Time".bold(), self.processing_time_ms);

        if !self.transformations.is_empty() {
            println!("\n{}", "Transformations:".bold().underline());
            for t in &self.transformations {
                println!(
                    "  {} ({}) at {}-{} -> {}",
                    t.pii_type.to_string().yellow(),
                    t.strategy,
                    t.original_start,
                    t.original_end,
                    t.replacement,
                );
            }
        }
    }

    fn print_table_row(&self) {
        println!(
            "{}\t{}",
            self.entity_count,
            crate::output::truncate(&self.anonymized_text, 60),
        );
    }

    fn print_plain(&self) {
        println!("{}", self.anonymized_text);
    }
}

// Helper functions for colored status output
fn format_status(status: &str) -> colored::ColoredString {
    use colored::Colorize;

    match status {
        "active" => "active".green(),
        "pending" => "pending".yellow(),
        "archived" => "archived".blue(),
        "deleting" => "deleting".red(),
        "failed" => "failed".red().bold(),
        _ => status.normal(),
    }
}

fn format_pii_status(status: &str) -> colored::ColoredString {
    use colored::Colorize;

    match status {
        "clean" => "clean".green(),
        "detected" => "detected".yellow().bold(),
        "pending" => "pending".blue(),
        "scanning" => "scanning".cyan(),
        "failed" => "failed".red(),
        _ => status.normal(),
    }
}
