use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use crate::error::{EnvzError, Result};

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| EnvzError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| EnvzError::Crypto(e.to_string()))?;

    Ok((nonce_bytes.to_vec(), ciphertext))
}

pub fn decrypt(key: &[u8; 32], nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| EnvzError::Crypto(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EnvzError::AuthFailed)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"hello world secret data";

        let (nonce, ciphertext) = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let plaintext = b"secret";

        let (nonce, ciphertext) = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = generate_key();
        let plaintext = b"secret";

        let (nonce, mut ciphertext) = encrypt(&key, plaintext).unwrap();
        ciphertext[0] ^= 0xff;

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_unique_nonces() {
        let key = generate_key();
        let plaintext = b"same data";

        let (nonce1, _) = encrypt(&key, plaintext).unwrap();
        let (nonce2, _) = encrypt(&key, plaintext).unwrap();

        assert_ne!(nonce1, nonce2);
    }
}
