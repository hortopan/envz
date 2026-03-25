use std::path::Path;

use crate::error::{EnvzError, Result};
use crate::store;

pub fn execute(pair: &str, vault_path: Option<&Path>) -> Result<()> {
    let Some((key, value)) = pair.split_once('=') else {
        return Err(EnvzError::ParseError("Expected KEY=VALUE format".into()));
    };

    let key = key.trim().to_string();
    store::validate_key(&key)?;
    let value = value.to_string();

    let mut vault = store::read_vault(vault_path)?;
    let (mut data, master_key) = store::open_vault(&vault)?;
    let existed = data.insert(key.clone(), value).is_some();
    store::seal_vault(&mut vault, &master_key, &data)?;
    store::write_vault(&vault, vault_path)?;

    if existed {
        eprintln!("Updated: {key}");
    } else {
        eprintln!("Set: {key}");
    }

    Ok(())
}
