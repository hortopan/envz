use crate::error::{EnvzError, Result};
use crate::store;

pub fn execute(key: &str) -> Result<()> {
    let mut vault = store::read_vault()?;
    let (mut data, master_key) = store::open_vault(&vault)?;

    if data.remove(key).is_none() {
        return Err(EnvzError::KeyNotFound(key.to_string()));
    }

    store::seal_vault(&mut vault, &master_key, &data)?;
    store::write_vault(&vault)?;

    eprintln!("Deleted: {key}");
    Ok(())
}
