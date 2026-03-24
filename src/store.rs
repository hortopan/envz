use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use zeroize::{Zeroize, Zeroizing};

use crate::biometric;
use crate::crypto;
use crate::error::{EnvzError, Result};
use crate::keychain;

/// Decrypted vault contents: sorted key-value pairs and the derived master key.
pub type VaultData = (BTreeMap<String, String>, Zeroizing<[u8; 32]>);

const VAULT_FILENAME: &str = ".envz";

const BUNDLE_ID: &str = match option_env!("ENVZ_BUNDLE_ID") {
    Some(id) => id,
    None => "net.gnarlylabs.envz",
};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Algorithm {
    #[serde(rename = "AES-256-GCM")]
    Aes256Gcm,
}

#[derive(Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub algorithm: Algorithm,
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

pub fn vault_id() -> &'static str {
    BUNDLE_ID
}

/// Returns the build-time app secret, decrypted from the binary at runtime.
/// The secret is XOR-encrypted via litcrypt so it's not visible via `strings`.
pub fn app_secret() -> String {
    lc_env!("ENVZ_APP_SECRET")
}

pub fn read_vault() -> Result<VaultFile> {
    let path = vault_path();
    if !path.exists() {
        return Err(EnvzError::VaultNotFound);
    }
    let data = fs::read_to_string(&path)?;
    let vault: VaultFile =
        serde_json::from_str(&data).map_err(|e| EnvzError::InvalidVault(e.to_string()))?;
    if vault.version != 1 {
        return Err(EnvzError::InvalidVault(format!(
            "unsupported vault version: {} (expected 1)",
            vault.version
        )));
    }
    Ok(vault)
}

pub fn write_vault(vault: &VaultFile) -> Result<()> {
    let path = vault_path();
    let tmp_path = path.with_file_name(format!(".envz.{}.tmp", std::process::id()));
    let data =
        serde_json::to_string_pretty(vault).map_err(|e| EnvzError::InvalidVault(e.to_string()))?;
    fs::write(&tmp_path, &data)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
}

pub fn create_vault(key: &[u8; 32], data: &BTreeMap<String, String>) -> Result<VaultFile> {
    let mut plaintext = serde_json::to_vec(data).map_err(|e| EnvzError::Crypto(e.to_string()))?;
    let (nonce, ciphertext) = crypto::encrypt(key, &plaintext)?;
    plaintext.zeroize();
    let now = Utc::now().to_rfc3339();

    Ok(VaultFile {
        version: 1,
        algorithm: Algorithm::Aes256Gcm,
        nonce: BASE64.encode(&nonce),
        ciphertext: BASE64.encode(&ciphertext),
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Open the vault: authenticate via Touch ID, retrieve the seed from keychain,
/// derive the AES key via HKDF(seed, codesign_hash || vault_id), and decrypt.
/// Returns both the data and the derived key for subsequent re-encryption.
pub fn open_vault(vault: &VaultFile) -> Result<VaultData> {
    biometric::authenticate("access envz vault")?;
    let mut seed_vec = keychain::retrieve_key(vault_id())?;
    let mut seed: [u8; 32] = seed_vec
        .as_slice()
        .try_into()
        .map_err(|_| EnvzError::Keychain("Invalid seed length".into()))?;
    seed_vec.zeroize();

    let codesign_hash = crate::codesign::signing_identity_hash()?;
    let master_key = crypto::derive_key(&seed, &codesign_hash, vault_id(), &app_secret())?;
    seed.zeroize();

    let nonce = BASE64
        .decode(&vault.nonce)
        .map_err(|e| EnvzError::InvalidVault(format!("bad nonce: {e}")))?;
    let ciphertext = BASE64
        .decode(&vault.ciphertext)
        .map_err(|e| EnvzError::InvalidVault(format!("bad ciphertext: {e}")))?;

    let mut plaintext = crypto::decrypt(&master_key, &nonce, &ciphertext)?;
    let data: BTreeMap<String, String> = serde_json::from_slice(&plaintext)
        .map_err(|e| EnvzError::InvalidVault(format!("corrupted data: {e}")))?;
    plaintext.zeroize();

    Ok((data, Zeroizing::new(master_key)))
}

/// Re-encrypt vault data using an already-retrieved master key.
pub fn seal_vault(
    vault: &mut VaultFile,
    key: &[u8; 32],
    data: &BTreeMap<String, String>,
) -> Result<()> {
    let mut plaintext = serde_json::to_vec(data).map_err(|e| EnvzError::Crypto(e.to_string()))?;
    let (nonce, ciphertext) = crypto::encrypt(key, &plaintext)?;
    plaintext.zeroize();

    vault.nonce = BASE64.encode(&nonce);
    vault.ciphertext = BASE64.encode(&ciphertext);
    vault.updated_at = Utc::now().to_rfc3339();

    Ok(())
}

/// Validate that a key is a valid environment variable name: [A-Za-z_][A-Za-z0-9_]*
pub fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(EnvzError::InvalidKey(key.to_string()));
    }
    let first = key.as_bytes()[0];
    if !first.is_ascii_alphabetic() && first != b'_' {
        return Err(EnvzError::InvalidKey(key.to_string()));
    }
    if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(EnvzError::InvalidKey(key.to_string()));
    }
    Ok(())
}

pub fn parse_env_file(contents: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();

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
        validate_key(&key).map_err(|_| {
            EnvzError::ParseError(format!("line {}: invalid key '{key}'", line_num + 1))
        })?;

        let value = value.trim();
        let value = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
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

    #[test]
    fn test_validate_key_valid() {
        assert!(validate_key("FOO").is_ok());
        assert!(validate_key("_BAR").is_ok());
        assert!(validate_key("a1_B2").is_ok());
    }

    #[test]
    fn test_validate_key_invalid() {
        assert!(validate_key("").is_err());
        assert!(validate_key("1ABC").is_err());
        assert!(validate_key("FOO BAR").is_err());
        assert!(validate_key("FOO;BAR").is_err());
        assert!(validate_key("FOO=BAR").is_err());
    }
}
