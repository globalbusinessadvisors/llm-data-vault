//! Shell completion generation commands.

use std::io;

use clap::{Args, Command};
use clap_complete::{generate, Shell};

use crate::output::CliError;

/// Shell completion generation commands.
#[derive(Args)]
pub struct CompletionCommands {
    /// Shell to generate completions for
    #[arg(value_enum)]
    shell: Shell,
}

impl CompletionCommands {
    /// Runs the completion command.
    pub fn run(self) -> Result<(), CliError> {
        let mut cmd = super::Cli::augment_args(Command::new("vault"));
        generate(self.shell, &mut cmd, "vault", &mut io::stdout());
        Ok(())
    }
}

/// Instructions for installing shell completions.
pub fn install_instructions(shell: Shell) -> String {
    match shell {
        Shell::Bash => r#"
# Add to ~/.bashrc or ~/.bash_profile:
eval "$(vault completion bash)"

# Or save to a file:
vault completion bash > /etc/bash_completion.d/vault
"#.to_string(),

        Shell::Zsh => r#"
# Add to ~/.zshrc:
eval "$(vault completion zsh)"

# Or save to a file:
vault completion zsh > "${fpath[1]}/_vault"
"#.to_string(),

        Shell::Fish => r#"
# Add to ~/.config/fish/config.fish:
vault completion fish | source

# Or save to a file:
vault completion fish > ~/.config/fish/completions/vault.fish
"#.to_string(),

        Shell::PowerShell => r#"
# Add to your PowerShell profile:
vault completion powershell | Out-String | Invoke-Expression

# Or save to a file:
vault completion powershell > vault.ps1
. ./vault.ps1
"#.to_string(),

        Shell::Elvish => r#"
# Add to ~/.elvish/rc.elv:
eval (vault completion elvish)

# Or save to a file:
vault completion elvish > ~/.elvish/lib/vault.elv
"#.to_string(),

        _ => "See documentation for completion installation instructions.".to_string(),
    }
}
