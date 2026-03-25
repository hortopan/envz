use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "envz",
    version,
    about = "Secure environment variables for macOS",
    long_about = "Secure environment variable management for macOS.\n\n\
        Encrypts secrets at rest using AES-256-GCM and stores decryption keys\n\
        in your macOS Keychain with Touch ID authentication. Designed to protect\n\
        secrets from exposure to AI agents, shell tools, and untrusted processes.",
    after_help = "Quick start:\n  \
        envz init .env          Import from an existing .env file\n  \
        envz set API_KEY=sk-... Store a secret\n  \
        envz run -- npm start   Run a command with secrets injected\n  \
        source <(envz env)      Load secrets into current shell\n  \
        envz unsafe -- agent    Run untrusted tool without secrets"
)]
pub struct Cli {
    /// Path to the vault file (default: .envz in current directory)
    #[arg(short = 'v', long = "vault", global = true, env = "ENVZ_VAULT")]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new encrypted vault in the current directory
    #[command(
        long_about = "Create a new encrypted vault in the current directory.\n\n\
            Optionally imports variables from an existing .env file. The vault is \
            encrypted with AES-256-GCM and the decryption seed is stored in your \
            macOS Keychain, accessible only via Touch ID."
    )]
    Init {
        /// Import variables from this .env file
        file: Option<PathBuf>,

        /// Overwrite an existing vault instead of erroring
        #[arg(long)]
        force: bool,
    },

    /// Run a command with vault secrets injected as environment variables
    #[command(
        long_about = "Run a command with vault secrets injected as environment variables.\n\n\
            Authenticates via Touch ID, decrypts the vault, and passes all stored \
            variables to the subprocess. The parent environment is inherited as well."
    )]
    Run {
        /// Command and arguments (use -- to separate from envz flags)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Run a command with only safe system environment variables (no secrets)
    #[command(
        long_about = "Run a command with only safe system environment variables.\n\n\
            Strips all environment variables except a curated safe list (PATH, HOME,\n\
            SHELL, TERM, LANG, etc.). Use this to run untrusted tools like AI agents\n\
            or third-party scripts without exposing any secrets."
    )]
    Unsafe {
        /// Command and arguments (use -- to separate from envz flags)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Store a secret in the vault
    #[command(long_about = "Store a secret in the vault.\n\n\
        Authenticates via Touch ID, then encrypts and saves the key-value pair.\n\
        If the key already exists, its value is updated.")]
    Set {
        /// Secret to store, e.g. API_KEY=sk-secret-key
        #[arg(value_name = "KEY=VALUE")]
        pair: String,
    },

    /// Retrieve a single secret by name
    Get {
        /// Variable name to look up
        #[arg(value_name = "KEY")]
        key: String,
    },

    /// Remove a secret from the vault
    Delete {
        /// Variable name to delete
        #[arg(value_name = "KEY")]
        key: String,
    },

    /// List all stored variables and their values
    List,

    /// Print shell export statements for all secrets
    #[command(long_about = "Print shell export statements for all secrets.\n\n\
            Use with shell process substitution to load secrets into your current session:\n  \
            source <(envz env)")]
    Env,

    /// Print shell unset statements for all secrets
    #[command(long_about = "Print shell unset statements for all secrets.\n\n\
            Use with shell process substitution to remove secrets from your current session:\n  \
            source <(envz unenv)")]
    Unenv,

    /// Remove all secrets from the vault (with confirmation)
    Clear,
}
