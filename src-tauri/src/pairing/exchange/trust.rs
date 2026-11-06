use super::crypto::{hex_decode, hex_encode, now_ms};
use crate::pairing::PairingExchangeError;
use crate::storage::PeerRecord;

use rand::Rng;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const SESSION_TOKEN_LIFETIME_MS: u64 = 5 * 60 * 1000;
pub(crate) const SESSION_TOKEN_BYTES: usize = 32;
const TOKEN_HASH_DOMAIN: &[u8] = b"peerbay-pairing-token";

/// Builds the local trust record for the peer identified by `exchange`
pub fn build_peer_record(
    peer_device_id: &str,
    peer_fingerprint: &str,
    display_name: impl Into<String>,
    platform: impl Into<String>,
) -> Result<PeerRecord, PairingExchangeError> {
    PeerRecord::validate_fingerprint(peer_fingerprint)
        .map_err(|_| PairingExchangeError::InvalidCertificateFingerprint)?;
    PeerRecord::validate_device_id(peer_device_id)
        .map_err(|_| PairingExchangeError::InvalidDeviceId)?;

    let created_at = now_ms();
    let mut record = PeerRecord::new(
        peer_device_id.to_owned(),
        display_name,
        platform,
        peer_fingerprint.to_owned(),
        String::new(),
        "ip".to_owned(),
    );
    record.created_at = created_at;
    Ok(record)
}

/// Generates a session token and stores the SHA-256 hash of that token on `record.pairing_token_hash`
pub fn issue_session_token(record: &mut PeerRecord) -> Result<String, PairingExchangeError> {
    let mut token = vec![0_u8; SESSION_TOKEN_BYTES];
    rand::rng().fill_bytes(&mut token);

    let token_hex = hex_encode(&token);
    record.pairing_token_hash = hash_session_token(&token);

    token.zeroize();
    Ok(token_hex)
}

pub fn hash_presented_token(token_hex: &str) -> Result<String, PairingExchangeError> {
    let decoded = hex_decode(token_hex).map_err(|_| PairingExchangeError::InvalidSessionToken)?;
    if decoded.len() != SESSION_TOKEN_BYTES {
        return Err(PairingExchangeError::InvalidSessionToken);
    }
    let token = Zeroizing::new(decoded);
    Ok(hash_session_token(&token))
}

fn hash_session_token(token: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_HASH_DOMAIN);
    hasher.update(token);
    hex_encode(hasher.finalize().as_slice())
}
