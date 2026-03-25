use std::path::Path;

use crate::error::Result;
use crate::store;

pub fn execute(vault_path: Option<&Path>) -> Result<()> {
    let vault = store::read_vault(vault_path)?;
    let (data, _) = store::open_vault(&vault)?;

    for (key, value) in &data {
        // Use $'...' syntax to safely handle all special characters
        let escaped = value
            .replace('\\', "\\\\")
            .replace('\'', "\\'")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
            .replace('\0', "\\0");
        println!("export {key}=$'{escaped}'");
    }

    Ok(())
}
