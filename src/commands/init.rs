use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use crate::biometric;
use crate::crypto;
use crate::error::{EnvzError, Result};
use crate::keychain;
use crate::store;

pub fn execute(file: Option<PathBuf>, force: bool, vault_path: Option<&Path>) -> Result<()> {
    if store::vault_exists(vault_path) && !force {
        return Err(EnvzError::VaultAlreadyExists);
    }

    if !biometric::is_available() {
        return Err(EnvzError::Keychain(
            "Touch ID is required but not available on this system.".into(),
        ));
    }

    let data = match file {
        Some(ref path) => {
            let contents = fs::read_to_string(path).map_err(|e| {
                EnvzError::ParseError(format!("Cannot read '{}': {e}", path.display()))
            })?;
            store::parse_env_file(&contents)?
        }
        None => BTreeMap::new(),
    };

    // Reuse existing seed from keychain if available, otherwise generate a new one.
    // This allows multiple vaults to share a single keychain entry.
    // The actual AES key is derived at runtime via HKDF(seed, codesign_hash || vault_id).
    let mut seed = match keychain::retrieve_key(store::vault_id()) {
        Ok(existing) => {
            let s: [u8; 32] = existing
                .as_slice()
                .try_into()
                .map_err(|_| EnvzError::Keychain("Invalid seed length".into()))?;
            s
        }
        Err(_) => {
            let s = crypto::generate_seed();
            keychain::store_key(store::vault_id(), &s)?;
            s
        }
    };

    let codesign_hash = crate::codesign::signing_identity_hash()?;
    let mut key = crypto::derive_key(
        &seed,
        &codesign_hash,
        store::vault_id(),
        &store::app_secret(),
    )?;
    seed.zeroize();

    let vault = store::create_vault(&key, &data)?;
    key.zeroize();
    store::write_vault(&vault, vault_path)?;

    let count = data.len();
    eprintln!("Vault created with Touch ID protection.");
    if count > 0 {
        eprintln!("{count} variable(s) imported.");
        if let Some(ref path) = file {
            let confirm = dialoguer::Confirm::new()
                .with_prompt(format!("Delete the plaintext file '{}'?", path.display()))
                .default(true)
                .interact()
                .unwrap_or(false);
            if confirm {
                fs::remove_file(path)?;
                eprintln!("Deleted '{}'.", path.display());
            }
        }
    } else {
        eprintln!("Use `envz set KEY=VALUE` to add secrets.");
    }

    Ok(())
}
