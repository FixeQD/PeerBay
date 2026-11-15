use std::fs;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

pub const PEERBAY_MAGIC: &[u8] = b"PEERBAYENC";
pub const CURRENT_CIPHER_VERSION: u8 = 2;

const SALT_LENGTH: usize = 16;

pub fn derive_cipher_key(seed: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut derived = Zeroizing::new([0_u8; 32]);
    let params = Params::new(19456, 2, 1, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(seed.as_bytes(), salt, derived.as_mut())
        .expect("argon2 key derivation");
    derived
}

/// Custom format: PEERBAYENC + version(1) + salt(16) + nonce_len(1) + payload_len(4 LE) + nonce + ciphertext
pub fn encrypt_custom(data: &[u8], seed: &str) -> Vec<u8> {
    let salt: [u8; SALT_LENGTH] = rand::random();
    let key_bytes = derive_cipher_key(seed, &salt);
    let key = aes_gcm::Key::<Aes256Gcm>::try_from(key_bytes.as_slice()).expect("valid key length");
    let cipher = Aes256Gcm::new(&key);

    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::try_from(&nonce_bytes[..]).expect("valid nonce length");
    let ciphertext = cipher.encrypt(&nonce, data).expect("AES-GCM encrypt");

    let payload_len = ciphertext.len() as u32;

    let mut bundle =
        Vec::with_capacity(10 + 1 + SALT_LENGTH + 1 + 4 + nonce_bytes.len() + ciphertext.len());
    bundle.extend_from_slice(PEERBAY_MAGIC);
    bundle.push(CURRENT_CIPHER_VERSION);
    bundle.extend_from_slice(&salt);
    bundle.push(nonce_bytes.len() as u8);
    bundle.extend_from_slice(&payload_len.to_le_bytes());
    bundle.extend_from_slice(&nonce_bytes);
    bundle.extend_from_slice(&ciphertext);
    bundle
}

/// Verify header magic, version, lengths, then decrypt with the GCM authentication tag.
pub fn decrypt_custom(data: &[u8], seed: &str) -> Option<Vec<u8>> {
    let header_size = 10 + 1 + SALT_LENGTH + 1 + 4;
    if data.len() < header_size + 12 {
        return None;
    }
    if &data[..10] != PEERBAY_MAGIC {
        return None;
    }
    let version = data[10];
    if version != CURRENT_CIPHER_VERSION {
        return None;
    }
    let salt = &data[11..11 + SALT_LENGTH];
    let nonce_len = data[11 + SALT_LENGTH] as usize;
    if nonce_len != 12 {
        return None;
    }
    let payload_offset = 11 + SALT_LENGTH + 1;
    let payload_len = u32::from_le_bytes([
        data[payload_offset],
        data[payload_offset + 1],
        data[payload_offset + 2],
        data[payload_offset + 3],
    ]) as usize;
    let nonce_offset = payload_offset + 4;
    if data.len() != nonce_offset + nonce_len + payload_len {
        return None;
    }
    let nonce = Nonce::try_from(&data[nonce_offset..nonce_offset + nonce_len]).ok()?;
    let ciphertext = &data[nonce_offset + nonce_len..];
    let key_bytes = derive_cipher_key(seed, salt);
    let key = aes_gcm::Key::<Aes256Gcm>::try_from(key_bytes.as_slice()).expect("valid key length");
    let cipher = Aes256Gcm::new(&key);
    cipher.decrypt(&nonce, ciphertext).ok()
}

pub fn write_custom_atomic(path: &Path, plaintext: &[u8], seed: &str) -> std::io::Result<()> {
    let encrypted = encrypt_custom(plaintext, seed);
    let tmp_path = path.with_extension("tmp.pbz");
    fs::write(&tmp_path, &encrypted)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

pub fn read_custom_atomic(path: &Path, seed: &str) -> Option<Vec<u8>> {
    let encrypted = fs::read(path).ok()?;
    decrypt_custom(&encrypted, seed)
}
