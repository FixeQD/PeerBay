use std::fs;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

const SALT_LENGTH: usize = 16;

pub fn derive_local_key(seed: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut derived = Zeroizing::new([0_u8; 32]);
    let params = Params::new(19456, 2, 1, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(seed.as_bytes(), salt, derived.as_mut())
        .expect("argon2 key derivation");
    derived
}

pub fn encrypt_local(data: &[u8], seed: &str) -> Vec<u8> {
    let salt: [u8; SALT_LENGTH] = rand::random();
    let key_bytes = derive_local_key(seed, &salt);
    let key = aes_gcm::Key::<Aes256Gcm>::try_from(key_bytes.as_slice()).expect("valid key length");
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = aes_gcm::Nonce::try_from(&nonce_bytes[..]).expect("valid nonce length");
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .expect("AES-GCM encryption failure");
    let mut result = Vec::with_capacity(SALT_LENGTH + 12 + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    result
}

pub fn decrypt_local(data: &[u8], seed: &str) -> Option<Vec<u8>> {
    if data.len() < SALT_LENGTH + 12 {
        return None;
    }
    let salt = &data[..SALT_LENGTH];
    let nonce = aes_gcm::Nonce::try_from(&data[SALT_LENGTH..SALT_LENGTH + 12]).ok()?;
    let ciphertext = &data[SALT_LENGTH + 12..];
    let key_bytes = derive_local_key(seed, salt);
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
