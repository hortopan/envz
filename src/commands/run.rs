use std::process::{self, Command};

use crate::error::{EnvzError, Result};
use crate::store;

pub fn execute(command: &[String]) -> Result<()> {
    if command.is_empty() {
        return Err(EnvzError::CommandError("No command specified".into()));
    }

    let vault = store::read_vault()?;
    let (data, _) = store::open_vault(&vault)?;

    let status = Command::new(&command[0])
        .args(&command[1..])
        .envs(&data)
        .status()
        .map_err(|e| EnvzError::CommandError(format!("Failed to execute '{}': {e}", command[0])))?;

    process::exit(status.code().unwrap_or(1));
}
