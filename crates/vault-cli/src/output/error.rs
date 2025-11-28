//! CLI error types and handling.

use std::process::ExitCode;

use colored::Colorize;

/// CLI error type.
#[derive(Debug)]
pub struct CliError {
    /// Error kind.
    pub kind: ErrorKind,
    /// Error message.
    pub message: String,
    /// Underlying cause.
    pub cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}

/// Error kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Configuration error.
    Config,
    /// API error.
    Api,
    /// Authentication error.
    Auth,
    /// Validation error.
    Validation,
    /// IO error.
    Io,
    /// Output/formatting error.
    Output,
    /// User cancelled operation.
    Cancelled,
    /// Internal error.
    Internal,
}

impl CliError {
    /// Creates a new CLI error.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            cause: None,
        }
    }

    /// Creates a new CLI error with a cause.
    pub fn with_cause<E>(kind: ErrorKind, message: impl Into<String>, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            kind,
            message: message.into(),
            cause: Some(Box::new(cause)),
        }
    }

    /// Creates a configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config, message)
    }

    /// Creates an API error.
    pub fn api(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Api, message)
    }

    /// Creates an authentication error.
    pub fn auth(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Auth, message)
    }

    /// Creates a validation error.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Validation, message)
    }

    /// Creates an IO error.
    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, message)
    }

    /// Creates an output error.
    pub fn output(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Output, message)
    }

    /// Creates a cancelled error.
    pub fn cancelled() -> Self {
        Self::new(ErrorKind::Cancelled, "Operation cancelled")
    }

    /// Returns the exit code for this error.
    pub fn exit_code(&self) -> ExitCode {
        match self.kind {
            ErrorKind::Config => ExitCode::from(2),
            ErrorKind::Api => ExitCode::from(1),
            ErrorKind::Auth => ExitCode::from(3),
            ErrorKind::Validation => ExitCode::from(4),
            ErrorKind::Io => ExitCode::from(5),
            ErrorKind::Output => ExitCode::from(6),
            ErrorKind::Cancelled => ExitCode::from(130),
            ErrorKind::Internal => ExitCode::from(255),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(ref cause) = self.cause {
            write!(f, ": {cause}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_ref().map(|e| e.as_ref() as _)
    }
}

impl From<vault_sdk::Error> for CliError {
    fn from(error: vault_sdk::Error) -> Self {
        let kind = match &error {
            vault_sdk::Error::Unauthorized { .. } | vault_sdk::Error::Forbidden { .. } => {
                ErrorKind::Auth
            }
            vault_sdk::Error::BadRequest { .. } => ErrorKind::Validation,
            vault_sdk::Error::Configuration { .. } => ErrorKind::Config,
            vault_sdk::Error::Io(_) => ErrorKind::Io,
            _ => ErrorKind::Api,
        };

        Self::with_cause(kind, error.to_string(), error)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::with_cause(ErrorKind::Io, "IO error", error)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::with_cause(ErrorKind::Output, "JSON error", error)
    }
}

impl From<toml::de::Error> for CliError {
    fn from(error: toml::de::Error) -> Self {
        Self::with_cause(ErrorKind::Config, "Configuration error", error)
    }
}

/// Prints an error to stderr.
pub fn print_error(error: &CliError) {
    let prefix = match error.kind {
        ErrorKind::Config => "Configuration error",
        ErrorKind::Api => "API error",
        ErrorKind::Auth => "Authentication error",
        ErrorKind::Validation => "Validation error",
        ErrorKind::Io => "IO error",
        ErrorKind::Output => "Output error",
        ErrorKind::Cancelled => "Cancelled",
        ErrorKind::Internal => "Internal error",
    };

    eprintln!("{} {}", format!("{}:", prefix).red().bold(), error.message);

    if let Some(ref cause) = error.cause {
        eprintln!("  {}", format!("Caused by: {cause}").dimmed());
    }

    // Print helpful hints based on error kind
    match error.kind {
        ErrorKind::Auth => {
            eprintln!();
            eprintln!("{}", "Hint: Check your API key or token. You can set it with:".dimmed());
            eprintln!("{}", "  export VAULT_API_KEY=your-key".dimmed());
            eprintln!("{}", "  vault config set api_key your-key".dimmed());
        }
        ErrorKind::Config => {
            eprintln!();
            eprintln!("{}", "Hint: Make sure your configuration is valid. Run:".dimmed());
            eprintln!("{}", "  vault config show".dimmed());
        }
        _ => {}
    }
}
