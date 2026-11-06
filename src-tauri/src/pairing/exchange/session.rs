use super::PairingExchange;
use super::*;
use crate::pairing::PairingExchangeError;
use crate::protocol::pairing::{
    PairingCode, PairingCommit, PairingConfirm, PairingNonce as ProtocolNonce, PairingReveal,
    PairingStart,
};

use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct PairingSession {
    inner: Arc<Mutex<PairingExchange>>,
}

impl PairingSession {
    pub fn new(exchange: PairingExchange) -> Self {
        Self {
            inner: Arc::new(Mutex::new(exchange)),
        }
    }

    pub fn state(&self) -> PairingExchangeState {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .state()
    }

    pub fn role(&self) -> PairingRole {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .role()
    }

    pub fn pairing_id(&self) -> String {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .pairing_id()
            .to_owned()
    }

    pub fn local_commitment(&self) -> String {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .local_commitment()
            .to_owned()
    }

    pub fn start_message(&self) -> Result<PairingStart, PairingExchangeError> {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .start_message()
    }

    pub fn apply_commit(&self, commit: &PairingCommit) -> Result<(), PairingExchangeError> {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .apply_commit(commit)
    }

    pub fn apply_start(&self, start: &PairingStart) -> Result<PairingCommit, PairingExchangeError> {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .apply_start(start)
    }

    pub fn reveal(&self) -> Result<ProtocolNonce, PairingExchangeError> {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .reveal()
    }

    pub fn apply_reveal(&self, reveal: &PairingReveal) -> Result<(), PairingExchangeError> {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .apply_reveal(reveal)
    }

    pub fn apply_nonce(&self, nonce: &ProtocolNonce) -> Result<(), PairingExchangeError> {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .apply_nonce(nonce)
    }

    pub fn sas_code(&mut self) -> Result<PairingSas, PairingExchangeError> {
        let mut guard = self.inner.lock().expect("pairing session mutex poisoned");
        guard.sas_code()
    }

    pub fn emit_pairing_code(
        &mut self,
        code_lifetime_ms: u64,
    ) -> Result<PairingCode, PairingExchangeError> {
        let mut guard = self.inner.lock().expect("pairing session mutex poisoned");
        guard.emit_pairing_code(code_lifetime_ms)
    }

    pub fn apply_pairing_code(
        &self,
        code: &crate::protocol::pairing::PairingCode,
    ) -> Result<(), PairingExchangeError> {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .apply_pairing_code(code)
    }

    pub fn verify_pairing_confirm(
        &mut self,
        confirm: &PairingConfirm,
    ) -> Result<(), PairingExchangeError> {
        let mut guard = self.inner.lock().expect("pairing session mutex poisoned");
        guard.verify_pairing_confirm(confirm)
    }

    /// Responder side: persist trust and issue the session token
    pub fn accept(
        &mut self,
        trust_store: &crate::storage::PeerTrustStore,
        display_name: impl Into<String>,
        platform: impl Into<String>,
    ) -> Result<crate::protocol::pairing::PairingAccepted, PairingExchangeError> {
        let mut guard = self.inner.lock().expect("pairing session mutex poisoned");
        guard.accept(trust_store, display_name, platform)
    }

    /// Initiator side: persist trust from the peer's accepted token
    pub fn apply_accepted(
        &mut self,
        trust_store: &crate::storage::PeerTrustStore,
        peer_device_id: impl Into<String>,
        accepted: &crate::protocol::pairing::PairingAccepted,
        display_name: impl Into<String>,
        platform: impl Into<String>,
    ) -> Result<(), PairingExchangeError> {
        let mut guard = self.inner.lock().expect("pairing session mutex poisoned");
        guard.apply_accepted(
            trust_store,
            peer_device_id,
            accepted,
            display_name,
            platform,
        )
    }

    pub fn expire_if_timed_out(&self) -> bool {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .expire_if_timed_out()
    }

    pub fn secrets_invalidated(&self) -> bool {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .secrets_invalidated()
    }

    pub fn cancel(&self) {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .cancel()
    }

    pub fn invalidate_secrets(&self) {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .invalidate_secrets()
    }

    pub fn is_expired(&self) -> bool {
        self.inner
            .lock()
            .expect("pairing session mutex poisoned")
            .is_expired()
    }
}

impl std::fmt::Debug for PairingSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingSession")
            .field("state", &self.state())
            .finish()
    }
}
