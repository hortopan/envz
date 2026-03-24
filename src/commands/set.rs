use crate::error::{EnvzError, Result};
use crate::store;

pub fn execute(pair: &str) -> Result<()> {
    let Some((key, value)) = pair.split_once('=') else {
        return Err(EnvzError::ParseError("Expected KEY=VALUE format".into()));
    };

    let key = key.trim().to_string();
    let value = value.to_string();

    if key.is_empty() {
        return Err(EnvzError::ParseError("Key cannot be empty".into()));
    }

    let mut vault = store::read_vault()?;
    let (mut data, master_key) = store::open_vault(&vault)?;
    let existed = data.insert(key.clone(), value).is_some();
    store::seal_vault(&mut vault, &master_key, &data)?;
    store::write_vault(&vault)?;

    if existed {
        eprintln!("Updated: {key}");
    } else {
        eprintln!("Set: {key}");
    }

    Ok(())
}
