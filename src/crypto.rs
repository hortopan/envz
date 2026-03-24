use crate::error::{EnvzError, Result};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

/// Generate a random 32-byte seed (stored in keychain, NOT the encryption key).
pub fn generate_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    seed
}

/// Derive the actual AES-256 encryption key from the seed using HKDF.
/// The info parameter binds the key to the binary's code signature, vault identity,
/// and an optional build-time app secret:
///   info = codesign_hash || vault_id [|| app_secret]
/// This ensures that even if the seed is extracted from the keychain, the correct
/// key can only be derived by a binary with the matching code signature and app secret.
pub fn derive_key(
    seed: &[u8; 32],
    codesign_hash: &[u8; 32],
    vault_id: &str,
    app_secret: &str,
) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, seed);

    // Build info: codesign_hash || len(vault_id) || vault_id || len(app_secret) || app_secret
    // Length prefixes prevent ambiguous concatenation of variable-length fields.
    let mut info = Vec::with_capacity(32 + 4 + vault_id.len() + 4 + app_secret.len());
    info.extend_from_slice(codesign_hash);
    info.extend_from_slice(&(vault_id.len() as u32).to_le_bytes());
    info.extend_from_slice(vault_id.as_bytes());
    info.extend_from_slice(&(app_secret.len() as u32).to_le_bytes());
    info.extend_from_slice(app_secret.as_bytes());

    let mut key = [0u8; 32];
    hk.expand(&info, &mut key)
        .map_err(|e| EnvzError::Crypto(format!("HKDF expand failed: {e}")))?;
    Ok(key)
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EnvzError::Crypto(e.to_string()))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

pub fn decrypt(key: &[u8; 32], nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if nonce_bytes.len() != 12 {
        return Err(EnvzError::Crypto(format!(
            "invalid nonce length: expected 12, got {}",
            nonce_bytes.len()
        )));
    }

    let cipher = Aes256Gcm::new(key.into());

    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        EnvzError::Crypto("decryption failed: invalid key or corrupted data".into())
    })?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_seed();
        let plaintext = b"hello world secret data";

        let (nonce, ciphertext) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_seed();
        let key2 = generate_seed();
        let plaintext = b"secret";

        let (nonce, ciphertext) = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = generate_seed();
        let plaintext = b"secret";

        let (nonce, mut ciphertext) = encrypt(&key, plaintext).unwrap();
        ciphertext[0] ^= 0xff;

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_unique_nonces() {
        let key = generate_seed();
        let plaintext = b"same data";

        let (nonce1, _) = encrypt(&key, plaintext).unwrap();
        let (nonce2, _) = encrypt(&key, plaintext).unwrap();

        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let seed = generate_seed();
        let hash = [0xABu8; 32];
        let vault_id = "net.gnarlylabs.test";

        let key1 = derive_key(&seed, &hash, vault_id, "test-secret").unwrap();
        let key2 = derive_key(&seed, &hash, vault_id, "test-secret").unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_codesign_gives_different_key() {
        let seed = generate_seed();
        let hash_a = [0xAAu8; 32];
        let hash_b = [0xBBu8; 32];
        let vault_id = "net.gnarlylabs.test";

        let key_a = derive_key(&seed, &hash_a, vault_id, "test-secret").unwrap();
        let key_b = derive_key(&seed, &hash_b, vault_id, "test-secret").unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_key_different_vault_id_gives_different_key() {
        let seed = generate_seed();
        let hash = [0xAAu8; 32];

        let key_a = derive_key(&seed, &hash, "vault-a", "test-secret").unwrap();
        let key_b = derive_key(&seed, &hash, "vault-b", "test-secret").unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_derive_key_different_app_secret_gives_different_key() {
        let seed = generate_seed();
        let hash = [0xAAu8; 32];
        let vault_id = "net.gnarlylabs.test";

        let key_a = derive_key(&seed, &hash, vault_id, "secret-a").unwrap();
        let key_b = derive_key(&seed, &hash, vault_id, "secret-b").unwrap();
        assert_ne!(key_a, key_b);
    }
}
