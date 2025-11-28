//! Authentication commands.

use clap::{Args, Subcommand};
use colored::Colorize;

use crate::config::Config;
use crate::output::{CliError, OutputFormat, success, info};

use super::ClientConfig;

/// Authentication and session management commands.
#[derive(Args)]
pub struct AuthCommands {
    #[command(subcommand)]
    pub command: AuthSubcommand,
}

/// Authentication subcommands.
#[derive(Subcommand)]
pub enum AuthSubcommand {
    /// Log in with username and password
    Login {
        /// Username or email
        #[arg(short, long)]
        username: Option<String>,

        /// Password (will prompt if not provided)
        #[arg(short, long)]
        password: Option<String>,

        /// Save token to config
        #[arg(long)]
        save: bool,
    },

    /// Log out and invalidate session
    Logout,

    /// Show current user info
    Whoami,

    /// Verify current token is valid
    Verify,

    /// Refresh access token
    Refresh {
        /// Refresh token (uses stored token if not provided)
        #[arg(short, long)]
        token: Option<String>,
    },

    /// Show session information
    Session,
}

impl AuthCommands {
    /// Runs the auth command.
    pub async fn run(self, config: &ClientConfig, format: OutputFormat) -> Result<(), CliError> {
        match self.command {
            AuthSubcommand::Login { username, password, save } => {
                Self::login(config, username, password, save).await
            }
            AuthSubcommand::Logout => Self::logout(config).await,
            AuthSubcommand::Whoami => Self::whoami(config, format).await,
            AuthSubcommand::Verify => Self::verify(config).await,
            AuthSubcommand::Refresh { token } => Self::refresh(config, token).await,
            AuthSubcommand::Session => Self::session(config, format).await,
        }
    }

    async fn login(
        config: &ClientConfig,
        username: Option<String>,
        password: Option<String>,
        save: bool,
    ) -> Result<(), CliError> {
        use dialoguer::{Input, Password};

        let username = match username {
            Some(u) => u,
            None => Input::new()
                .with_prompt("Username or email")
                .interact_text()
                .map_err(|e| CliError::io(format!("Failed to read input: {e}")))?,
        };

        let password = match password {
            Some(p) => p,
            None => Password::new()
                .with_prompt("Password")
                .interact()
                .map_err(|e| CliError::io(format!("Failed to read password: {e}")))?,
        };

        // Build client without auth for login
        let client = vault_sdk::VaultClient::builder()
            .base_url(&config.base_url)
            .build()?;

        let token_response = client.auth().login(&username, &password).await?;

        success(&format!(
            "Logged in successfully. Token expires in {}",
            crate::output::format_duration(token_response.expires_in)
        ));

        if save {
            let mut cfg = Config::load("default")?;
            cfg.token = Some(token_response.access_token.clone());
            cfg.save("default")?;
            info("Token saved to configuration");
        } else {
            println!("\n{}", "Access token (export as VAULT_TOKEN):".dimmed());
            println!("{}", token_response.access_token);

            if let Some(ref refresh) = token_response.refresh_token {
                println!("\n{}", "Refresh token:".dimmed());
                println!("{refresh}");
            }
        }

        Ok(())
    }

    async fn logout(config: &ClientConfig) -> Result<(), CliError> {
        let client = config.build_client()?;
        client.auth().logout().await?;

        // Clear saved token
        let mut cfg = Config::load("default")?;
        cfg.token = None;
        cfg.save("default")?;

        success("Logged out successfully");
        Ok(())
    }

    async fn whoami(config: &ClientConfig, _format: OutputFormat) -> Result<(), CliError> {
        let client = config.build_client()?;
        let user = client.auth().me().await?;

        println!("{}: {}", "User ID".bold(), user.id);
        println!("{}: {}", "Username".bold(), user.username);
        println!("{}: {}", "Email".bold(), user.email);

        if let Some(ref name) = user.display_name {
            println!("{}: {}", "Display Name".bold(), name);
        }

        println!("{}: {}", "Roles".bold(), user.roles.join(", "));
        println!(
            "{}: {}",
            "Status".bold(),
            if user.active { "Active".green() } else { "Inactive".red() }
        );

        Ok(())
    }

    async fn verify(config: &ClientConfig) -> Result<(), CliError> {
        let client = config.build_client()?;

        if client.auth().verify().await? {
            success("Token is valid");
            Ok(())
        } else {
            Err(CliError::auth("Token is invalid or expired"))
        }
    }

    async fn refresh(config: &ClientConfig, refresh_token: Option<String>) -> Result<(), CliError> {
        let cfg = Config::load("default")?;

        let refresh_token = refresh_token
            .or(cfg.token.clone())
            .ok_or_else(|| CliError::auth("No refresh token provided or stored"))?;

        let client = vault_sdk::VaultClient::builder()
            .base_url(&config.base_url)
            .build()?;

        let token_response = client.auth().refresh(&refresh_token).await?;

        success(&format!(
            "Token refreshed. New token expires in {}",
            crate::output::format_duration(token_response.expires_in)
        ));

        println!("\n{}", "New access token:".dimmed());
        println!("{}", token_response.access_token);

        Ok(())
    }

    async fn session(config: &ClientConfig, _format: OutputFormat) -> Result<(), CliError> {
        let client = config.build_client()?;
        let session = client.auth().session().await?;

        println!("{}: {}", "Session ID".bold(), session.session_id);
        println!("{}: {}", "User".bold(), session.user.username);
        println!(
            "{}: {}",
            "Expires".bold(),
            session.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
        println!("\n{}", "Permissions:".bold());
        for perm in &session.permissions {
            println!("  - {perm}");
        }

        Ok(())
    }
}
