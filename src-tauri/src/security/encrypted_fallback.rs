use std::fs;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub fn derive_local_key(seed: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(salt);
    Zeroizing::new(hasher.finalize().into())
}

pub fn encrypt_local(data: &[u8], seed: &str) -> Vec<u8> {
    let key_bytes = derive_local_key(seed, b"peerbay-local-fallback-v1");
    let key = aes_gcm::Key::<Aes256Gcm>::try_from(key_bytes.as_slice()).expect("valid key length");
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = aes_gcm::Nonce::try_from(&nonce_bytes[..]).expect("valid nonce length");
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .expect("AES-GCM encryption failure");
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

pub fn decrypt_local(data: &[u8], seed: &str) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let nonce = aes_gcm::Nonce::try_from(&data[..12]).ok()?;
    let ciphertext = &data[12..];
    let key_bytes = derive_local_key(seed, b"peerbay-local-fallback-v1");
    let key = aes_gcm::Key::<Aes256Gcm>::try_from(key_bytes.as_slice()).expect("valid key length");
    let cipher = Aes256Gcm::new(&key);
    cipher.decrypt(&nonce, ciphertext).ok()
}

pub fn write_encrypted_atomic(path: &Path, plaintext: &[u8], seed: &str) -> std::io::Result<()> {
    let encrypted = encrypt_local(plaintext, seed);
    let tmp_path = path.with_extension("tmp.enc");
    fs::write(&tmp_path, &encrypted)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

pub fn read_encrypted_atomic(path: &Path, seed: &str) -> Option<Vec<u8>> {
    let encrypted = fs::read(path).ok()?;
    decrypt_local(&encrypted, seed)
}
