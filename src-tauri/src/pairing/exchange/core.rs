use super::types::*;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const SAS_CODE_LENGTH: usize = 6;
pub struct PairingExchange {
    pub(crate) pairing_id: String,
    pub(crate) role: PairingRole,
    pub(crate) local_device_id: String,
    pub(crate) local_fingerprint: String,
    pub(crate) local_versions: Vec<u16>,
    pub(crate) local_nonce: Zeroizing<Vec<u8>>,
    pub(crate) local_commitment: String,
    pub(crate) peer_device_id: Option<String>,
    pub(crate) peer_fingerprint: Option<String>,
    pub(crate) peer_versions: Vec<u16>,
    pub(crate) peer_commitment: Option<String>,
    pub(crate) peer_nonce: Option<Zeroizing<Vec<u8>>>,
    pub(crate) state: PairingExchangeState,
    pub(crate) created_at: Instant,
    pub(crate) timeout: Duration,
    pub(crate) invalidated: bool,
    pub(crate) code_expires_at_ms: u64,
}

impl std::fmt::Debug for PairingExchange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingExchange")
            .field("pairing_id", &self.pairing_id)
            .field("state", &self.state)
            .field("role", &self.role)
            .field("local_nonce", &"<redacted>")
            .field("peer_nonce", &"<redacted>")
            .finish()
    }
}

impl Drop for PairingExchange {
    fn drop(&mut self) {
        self.invalidate_secrets();
    }
}
