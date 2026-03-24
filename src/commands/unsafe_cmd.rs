use std::process::{self, Command};

use crate::env_filter;
use crate::error::{EnvzError, Result};

pub fn execute(command: &[String]) -> Result<()> {
    if command.is_empty() {
        return Err(EnvzError::CommandError("No command specified".to_string()));
    }

    let safe_env = env_filter::filter_env();

    let status = Command::new(&command[0])
        .args(&command[1..])
        .env_clear()
        .envs(&safe_env)
        .status()
        .map_err(|e| EnvzError::CommandError(format!("Failed to execute '{}': {e}", command[0])))?;

    process::exit(status.code().unwrap_or(1));
}
