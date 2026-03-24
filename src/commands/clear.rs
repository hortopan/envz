use std::collections::BTreeMap;

use dialoguer::Confirm;

use crate::error::{EnvzError, Result};
use crate::store;

pub fn execute() -> Result<()> {
    let mut vault = store::read_vault()?;
    let (data, master_key) = store::open_vault(&vault)?;
    let count = data.len();

    if count == 0 {
        eprintln!("Vault is already empty.");
        return Ok(());
    }

    let confirmed = Confirm::new()
        .with_prompt(format!("Delete all {count} variable(s) from the vault?"))
        .default(false)
        .interact()
        .map_err(|e| EnvzError::Io(std::io::Error::other(e)))?;

    if !confirmed {
        eprintln!("Aborted.");
        return Ok(());
    }

    let empty: BTreeMap<String, String> = BTreeMap::new();
    store::seal_vault(&mut vault, &master_key, &empty)?;
    store::write_vault(&vault)?;

    eprintln!("Vault cleared.");
    Ok(())
}
