use std::collections::HashMap;
use std::fs;

use crate::biometric;
use crate::crypto;
use crate::error::{EnvzError, Result};
use crate::keychain;
use crate::store;

pub fn execute(file: Option<String>, biometric_flag: bool, force: bool) -> Result<()> {
    if store::vault_exists() && !force {
        return Err(EnvzError::VaultAlreadyExists);
    }

    // If biometric requested, verify Touch ID is available
    if biometric_flag && !biometric::is_available() {
        return Err(EnvzError::Keychain(
            "Touch ID not available. Use --no-biometric to initialize without it.".into(),
        ));
    }

    let data = match file {
        Some(ref path) => {
            let contents = fs::read_to_string(path)
                .map_err(|e| EnvzError::ParseError(format!("Cannot read '{path}': {e}")))?;
            store::parse_env_file(&contents)?
        }
        None => HashMap::new(),
    };

    let key = crypto::generate_key();
    let vault_id = store::compute_vault_id()?;
    keychain::store_key(&vault_id, &key)?;

    let vault = store::create_vault(&key, &data, biometric_flag, &vault_id)?;
    store::write_vault(&vault)?;

    let count = data.len();
    if biometric_flag {
        eprintln!("Vault created with Touch ID protection.");
    } else {
        eprintln!("Vault created.");
    }
    if count > 0 {
        eprintln!("{count} variable(s) imported.");
        if let Some(ref path) = file {
            eprintln!("Consider deleting the plaintext file: {path}");
        }
    } else {
        eprintln!("Use `envz set KEY=VALUE` to add secrets.");
    }

    Ok(())
}
