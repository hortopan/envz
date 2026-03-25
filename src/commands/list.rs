use std::path::Path;

use crate::error::Result;
use crate::store;

pub fn execute(vault_path: Option<&Path>) -> Result<()> {
    let vault = store::read_vault(vault_path)?;
    let (data, _) = store::open_vault(&vault)?;

    for (key, value) in &data {
        println!("{key}={value}");
    }

    Ok(())
}
