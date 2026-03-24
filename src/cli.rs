use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "envz", version, about = "Securely manage environment variables")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new envz vault, optionally importing from an existing env file
    Init {
        /// Path to an existing .env file to import
        file: Option<String>,

        /// Disable biometric (Touch ID) authentication and use keychain instead
        #[arg(long)]
        no_biometric: bool,

        /// Overwrite existing vault
        #[arg(long)]
        force: bool,
    },

    /// Run a command with decrypted environment variables
    Run {
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

/// Run a command with only safe system environment variables
    Unsafe {
        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Set an environment variable
    Set {
        /// KEY=VALUE pair
        pair: String,
    },

    /// Get an environment variable value
    Get {
        /// Variable name
        key: String,
    },

    /// Delete an environment variable
    Delete {
        /// Variable name
        key: String,
    },

    /// List all variables and their values
    List,

    /// Export all variables into the current shell (use with: source <(envz env))
    Env,

    /// Unset all variables from the current shell (use with: source <(envz unenv))
    Unenv,

    /// Remove all variables from the vault
    Clear,
}
