use crate::pairing::PairingExchangeError;
use rand::Rng;
use sha2::{Digest, Sha256};

const NONCE_LENGTH: usize = 32;

pub(super) fn generate_nonce() -> Result<Vec<u8>, PairingExchangeError> {
    let mut nonce = vec![0_u8; NONCE_LENGTH];
    rand::rng().fill_bytes(&mut nonce);
    Ok(nonce)
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(super) fn hex_decode(value: &str) -> Result<Vec<u8>, PairingExchangeError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(PairingExchangeError::InvalidNonce);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PairingExchangeError::InvalidNonce);
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for chunk in value.as_bytes().chunks(2) {
        let high = (chunk[0] as char)
            .to_digit(16)
            .ok_or(PairingExchangeError::InvalidNonce)?;
        let low = (chunk[1] as char)
            .to_digit(16)
            .ok_or(PairingExchangeError::InvalidNonce)?;
        bytes.push(((high << 4) | low) as u8);
    }
    Ok(bytes)
}

pub(super) fn hash_nonce(nonce: &[u8], pairing_id: &str, fingerprint: &str, role: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pairing_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(fingerprint.as_bytes());
    hasher.update(b"\0");
    hasher.update(role.as_bytes());
    hasher.update(b"\0");
    hasher.update(nonce);
    hex_encode(hasher.finalize().as_slice())
}

/// Current wall-clock time in milliseconds since the UNIX epoch
pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
