use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::biometric;
use crate::crypto;
use crate::error::{EnvzError, Result};
use crate::keychain;

const VAULT_FILENAME: &str = ".envz";

#[derive(Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub algorithm: String,
    pub biometric: bool,
    pub vault_id: String,
    pub nonce: String,
    pub ciphertext: String,
    pub created_at: String,
    pub updated_at: String,
}

pub fn vault_path() -> PathBuf {
    PathBuf::from(VAULT_FILENAME)
}

pub fn vault_exists() -> bool {
    vault_path().exists()
}

pub fn compute_vault_id() -> Result<String> {
    let abs_path = std::env::current_dir()?.join(VAULT_FILENAME);
    let mut hasher = Sha256::new();
    hasher.update(abs_path.to_string_lossy().as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn read_vault() -> Result<VaultFile> {
    let path = vault_path();
    if !path.exists() {
        return Err(EnvzError::VaultNotFound);
    }
    let data = fs::read_to_string(&path)?;
    serde_json::from_str(&data).map_err(|e| EnvzError::InvalidVault(e.to_string()))
}

pub fn write_vault(vault: &VaultFile) -> Result<()> {
    let path = vault_path();
    let tmp_path = path.with_extension("envz.tmp");
    let data =
        serde_json::to_string_pretty(vault).map_err(|e| EnvzError::InvalidVault(e.to_string()))?;
    fs::write(&tmp_path, &data)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

pub fn create_vault(
    key: &[u8; 32],
    data: &HashMap<String, String>,
    biometric: bool,
    vault_id: &str,
) -> Result<VaultFile> {
    let plaintext = serde_json::to_vec(data).map_err(|e| EnvzError::Crypto(e.to_string()))?;
    let (nonce, ciphertext) = crypto::encrypt(key, &plaintext)?;
    let now = Utc::now().to_rfc3339();

    Ok(VaultFile {
        version: 1,
        algorithm: "AES-256-GCM".to_string(),
        biometric,
        vault_id: vault_id.to_string(),
        nonce: BASE64.encode(&nonce),
        ciphertext: BASE64.encode(&ciphertext),
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Open the vault: authenticate (Touch ID if biometric), retrieve the master key,
/// and decrypt the data. Returns both the data and the master key for subsequent
/// re-encryption without hitting the keychain again.
pub fn open_vault(vault: &VaultFile) -> Result<(HashMap<String, String>, [u8; 32])> {
    if vault.biometric {
        biometric::authenticate("access envz vault")?;
    }
    let master_key_vec = keychain::retrieve_key(&vault.vault_id)?;
    let master_key: [u8; 32] = master_key_vec
        .as_slice()
        .try_into()
        .map_err(|_| EnvzError::Keychain("Invalid key length".into()))?;

    let nonce = BASE64
        .decode(&vault.nonce)
        .map_err(|e| EnvzError::InvalidVault(format!("bad nonce: {e}")))?;
    let ciphertext = BASE64
        .decode(&vault.ciphertext)
        .map_err(|e| EnvzError::InvalidVault(format!("bad ciphertext: {e}")))?;

    let plaintext = crypto::decrypt(&master_key, &nonce, &ciphertext)?;
    let data: HashMap<String, String> = serde_json::from_slice(&plaintext)
        .map_err(|e| EnvzError::InvalidVault(format!("corrupted data: {e}")))?;

    Ok((data, master_key))
}

/// Re-encrypt vault data using an already-retrieved master key.
pub fn seal_vault(
    vault: &mut VaultFile,
    key: &[u8; 32],
    data: &HashMap<String, String>,
) -> Result<()> {
    let plaintext = serde_json::to_vec(data).map_err(|e| EnvzError::Crypto(e.to_string()))?;
    let (nonce, ciphertext) = crypto::encrypt(key, &plaintext)?;

    vault.nonce = BASE64.encode(&nonce);
    vault.ciphertext = BASE64.encode(&ciphertext);
    vault.updated_at = Utc::now().to_rfc3339();

    Ok(())
}

pub fn parse_env_file(contents: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();

    for (line_num, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line);

        let Some((key, value)) = line.split_once('=') else {
            return Err(EnvzError::ParseError(format!(
                "line {}: missing '=' in '{line}'",
                line_num + 1
            )));
        };

        let key = key.trim().to_string();
        if key.is_empty() {
            return Err(EnvzError::ParseError(format!(
                "line {}: empty key",
                line_num + 1
            )));
        }

        let value = value.trim();
        let value = if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value[1..value.len() - 1].to_string()
        } else {
            value.to_string()
        };

        map.insert(key, value);
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_file_basic() {
        let input = "FOO=bar\nBAZ=qux\n";
        let map = parse_env_file(input).unwrap();
        assert_eq!(map.get("FOO").unwrap(), "bar");
        assert_eq!(map.get("BAZ").unwrap(), "qux");
    }

    #[test]
    fn test_parse_env_file_with_export() {
        let input = "export FOO=bar\nexport BAZ=qux\n";
        let map = parse_env_file(input).unwrap();
        assert_eq!(map.get("FOO").unwrap(), "bar");
    }

    #[test]
    fn test_parse_env_file_with_quotes() {
        let input = "FOO=\"hello world\"\nBAR='single quoted'\n";
        let map = parse_env_file(input).unwrap();
        assert_eq!(map.get("FOO").unwrap(), "hello world");
        assert_eq!(map.get("BAR").unwrap(), "single quoted");
    }

    #[test]
    fn test_parse_env_file_with_comments() {
        let input = "# comment\nFOO=bar\n\n# another\nBAZ=qux\n";
        let map = parse_env_file(input).unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn test_parse_env_file_missing_equals() {
        assert!(parse_env_file("INVALID\n").is_err());
    }
}
