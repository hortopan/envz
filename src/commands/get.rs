use crate::error::{EnvzError, Result};
use crate::store;

pub fn execute(key: &str) -> Result<()> {
    let vault = store::read_vault()?;
    let (data, _) = store::open_vault(&vault)?;

    match data.get(key) {
        Some(value) => {
            println!("{value}");
            Ok(())
        }
        None => Err(EnvzError::KeyNotFound(key.to_string())),
    }
}
