use std::fs;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const PEERBAY_MAGIC: &[u8] = b"PEERBAYENC";
pub const CURRENT_CIPHER_VERSION: u8 = 1;

pub fn derive_cipher_keys(seed: &str) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mut aes_hasher = Sha256::new();
    aes_hasher.update(seed.as_bytes());
    aes_hasher.update(b"peerbay-aes-v1");
    let aes_key: [u8; 32] = aes_hasher.finalize().into();

    let mut mac_hasher = Sha256::new();
    mac_hasher.update(seed.as_bytes());
    mac_hasher.update(b"peerbay-mac-v1");
    let mac_key: [u8; 32] = mac_hasher.finalize().into();
    (Zeroizing::new(aes_key), Zeroizing::new(mac_key))
}

pub fn compute_mac(data: &[u8], mac_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(mac_key.as_slice());
    hasher.update(data);
    hasher.finalize().into()
}

/// Custom format: PEERBAYENC + version(1) + nonce_len(1) + payload_len(4 LE) + nonce + ciphertext + mac(32)
pub fn encrypt_custom(data: &[u8], seed: &str) -> Vec<u8> {
    let (aes_key, mac_key) = derive_cipher_keys(seed);
    let key = aes_gcm::Key::<Aes256Gcm>::try_from(aes_key.as_slice()).expect("valid key length");
    let cipher = Aes256Gcm::new(&key);

    // 12-byte random nonce
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::try_from(&nonce_bytes[..]).expect("valid nonce length");
    let ciphertext = cipher.encrypt(&nonce, data).expect("AES-GCM encrypt");

    let payload_len = ciphertext.len() as u32;

    // Assemble header + ciphertext
    let mut bundle = Vec::with_capacity(10 + 1 + 4 + nonce_bytes.len() + ciphertext.len() + 32);
    bundle.extend_from_slice(PEERBAY_MAGIC); // 10
    bundle.push(CURRENT_CIPHER_VERSION); // 1
    bundle.push(nonce_bytes.len() as u8); // 1 (should be 12)
    bundle.extend_from_slice(&payload_len.to_le_bytes()); // 4
    bundle.extend_from_slice(&nonce_bytes); // 12
    bundle.extend_from_slice(&ciphertext);

    // Compute MAC over bundle
    let mac = compute_mac(&bundle, &mac_key);
    bundle.extend_from_slice(&mac); // 32
    bundle
}

/// Verify header magic, version, lengths, MAC, then decrypt.
pub fn decrypt_custom(data: &[u8], seed: &str) -> Option<Vec<u8>> {
    // Must have at least header + minimum payload + MAC
    if data.len() < 10 + 1 + 4 + 12 + 32 {
        return None;
    }
    // Magic check
    if &data[..10] != PEERBAY_MAGIC {
        return None;
    }
    let version = data[10];
    if version != CURRENT_CIPHER_VERSION {
        return None; // Unknown version rejected
    }
    let nonce_len = data[11] as usize;
    if nonce_len != 12 {
        return None; // Unexpected nonce length
    }
    let payload_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

    let header_size = 10 + 1 + 1 + 4; // magic + version + nonce_len + payload_len
    let header_plus_nonce = header_size + nonce_len;
    let mac_offset = header_plus_nonce + payload_len;

    if data.len() != mac_offset + 32 {
        return None;
    }

    // Split bundle and MAC
    let bundle = &data[..mac_offset];
    let mac_in = &data[mac_offset..mac_offset + 32];

    // Verify MAC
    let (aes_key, mac_key) = derive_cipher_keys(seed);
    let mac_expected = compute_mac(bundle, &mac_key);
    if mac_in != mac_expected.as_slice() {
        return None; // Tampering detected
    }

    // Extract nonce and ciphertext
    let nonce =
        Nonce::try_from(&bundle[header_size..header_size + nonce_len]).expect("valid nonce length");
    let ciphertext = &bundle[header_size + nonce_len..mac_offset];

    let key = aes_gcm::Key::<Aes256Gcm>::try_from(aes_key.as_slice()).expect("valid key length");
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
