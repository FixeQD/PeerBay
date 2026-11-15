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
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .state()
    }

    pub fn role(&self) -> PairingRole {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .role()
    }

    pub fn pairing_id(&self) -> String {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pairing_id()
            .to_owned()
    }

    pub fn local_commitment(&self) -> String {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .local_commitment()
            .to_owned()
    }

    pub fn start_message(&self) -> Result<PairingStart, PairingExchangeError> {
        self.inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?
            .start_message()
    }

    pub fn apply_commit(&self, commit: &PairingCommit) -> Result<(), PairingExchangeError> {
        self.inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?
            .apply_commit(commit)
    }

    pub fn apply_start(&self, start: &PairingStart) -> Result<PairingCommit, PairingExchangeError> {
        self.inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?
            .apply_start(start)
    }

    pub fn reveal(&self) -> Result<ProtocolNonce, PairingExchangeError> {
        self.inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?
            .reveal()
    }

    pub fn apply_reveal(&self, reveal: &PairingReveal) -> Result<(), PairingExchangeError> {
        self.inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?
            .apply_reveal(reveal)
    }

    pub fn apply_nonce(&self, nonce: &ProtocolNonce) -> Result<(), PairingExchangeError> {
        self.inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?
            .apply_nonce(nonce)
    }

    pub fn sas_code(&mut self) -> Result<PairingSas, PairingExchangeError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?;
        guard.sas_code()
    }

    pub fn emit_pairing_code(
        &mut self,
        code_lifetime_ms: u64,
    ) -> Result<PairingCode, PairingExchangeError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?;
        guard.emit_pairing_code(code_lifetime_ms)
    }

    pub fn apply_pairing_code(
        &self,
        code: &crate::protocol::pairing::PairingCode,
    ) -> Result<(), PairingExchangeError> {
        self.inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?
            .apply_pairing_code(code)
    }

    pub fn verify_pairing_confirm(
        &mut self,
        confirm: &PairingConfirm,
    ) -> Result<(), PairingExchangeError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?;
        guard.verify_pairing_confirm(confirm)
    }

    /// Responder side: persist trust and issue the session token
    pub fn accept(
        &mut self,
        trust_store: &crate::storage::PeerTrustStore,
        display_name: impl Into<String>,
        platform: impl Into<String>,
    ) -> Result<crate::protocol::pairing::PairingAccepted, PairingExchangeError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?;
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
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?;
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
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .expire_if_timed_out()
    }

    pub fn secrets_invalidated(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .secrets_invalidated()
    }

    pub fn cancel(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .cancel()
    }

    pub fn invalidate_secrets(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .invalidate_secrets()
    }

    pub fn is_expired(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    const DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const FINGERPRINT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn fresh_session() -> PairingSession {
        PairingSession::new(
            PairingExchange::as_initiator(
                "pair-lock-1".to_owned(),
                DEVICE_ID.to_owned(),
                FINGERPRINT.to_owned(),
                vec![1],
                Duration::from_secs(60),
            )
            .unwrap(),
        )
    }

    fn poison(session: &PairingSession) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = session.inner.lock().unwrap();
            panic!("poison the pairing session mutex");
        }));
    }

    #[test]
    fn poisoned_session_lock_fails_protocol_methods() {
        let mut session = fresh_session();
        poison(&session);
        assert_eq!(
            session.start_message().err(),
            Some(PairingExchangeError::SessionLockPoisoned)
        );
        assert_eq!(
            session.sas_code().err(),
            Some(PairingExchangeError::SessionLockPoisoned)
        );
    }

    #[test]
    fn poisoned_session_reads_recover_and_cleanup_still_works() {
        let session = fresh_session();
        let state_before = session.state();
        poison(&session);
        assert_eq!(session.state(), state_before);
        assert_eq!(session.pairing_id(), "pair-lock-1");
        session.cancel();
        assert_eq!(session.state(), PairingExchangeState::Cancelled);
        assert!(session.secrets_invalidated());
    }
}
