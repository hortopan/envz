#[derive(Debug, thiserror::Error)]
pub enum EnvzError {
    #[error("Vault not found. Run `envz init` first.")]
    VaultNotFound,

    #[error("Vault already exists in this directory. Use --force to overwrite.")]
    VaultAlreadyExists,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Authentication failed or was cancelled.")]
    AuthFailed,

    #[error("Encryption error: {0}")]
    Crypto(String),

    #[error("Keychain error: {0}")]
    Keychain(String),

    #[error("Invalid vault file: {0}")]
    InvalidVault(String),

    #[error("Invalid variable name '{0}': must match [A-Za-z_][A-Za-z0-9_]*")]
    InvalidKey(String),

    #[error("Failed to parse env file: {0}")]
    ParseError(String),

    #[error("Command failed: {0}")]
    CommandError(String),

    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, EnvzError>;
