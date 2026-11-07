use super::*;
use crate::pairing::PairingExchangeError;

use std::collections::BTreeMap;
use std::time::Duration;

const MAX_SESSIONS: usize = 64;

#[derive(Clone, Debug)]
pub struct PairingManager {
    sessions: std::sync::Arc<std::sync::Mutex<BTreeMap<String, PairingSession>>>,
    max_sessions: usize,
}

impl PairingManager {
    pub fn new() -> Self {
        Self {
            sessions: std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            max_sessions: MAX_SESSIONS,
        }
    }

    fn prune_expired(&self, sessions: &mut BTreeMap<String, PairingSession>) {
        let stale: Vec<String> = sessions
            .iter()
            .filter_map(|(id, session)| {
                let state = session.state();
                if matches!(
                    state,
                    PairingExchangeState::Completed
                        | PairingExchangeState::Cancelled
                        | PairingExchangeState::TimedOut
                        | PairingExchangeState::Rejected
                ) || session.is_expired()
                {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in stale {
            sessions.remove(&id);
        }
    }

    pub fn begin_initiator(
        &self,
        pairing_id: String,
        device_id: String,
        fingerprint: String,
        versions: Vec<u16>,
        timeout: Duration,
    ) -> Result<PairingSession, PairingExchangeError> {
        let exchange =
            PairingExchange::as_initiator(pairing_id, device_id, fingerprint, versions, timeout)?;
        self.insert(exchange)
    }

    pub fn insert(
        &self,
        exchange: PairingExchange,
    ) -> Result<PairingSession, PairingExchangeError> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("pairing manager mutex poisoned");
        self.prune_expired(&mut sessions);
        if sessions.len() >= self.max_sessions {
            return Err(PairingExchangeError::TooManySessions);
        }
        if sessions.contains_key(exchange.pairing_id()) {
            return Err(PairingExchangeError::DuplicateSession);
        }
        let session = PairingSession::new(exchange);
        sessions.insert(session.pairing_id(), session.clone());
        Ok(session)
    }

    pub fn get(&self, pairing_id: &str) -> Option<PairingSession> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("pairing manager mutex poisoned");
        self.prune_expired(&mut sessions);
        sessions.get(pairing_id).cloned()
    }

    pub fn remove(&self, pairing_id: &str) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .expect("pairing manager mutex poisoned");
        sessions.remove(pairing_id).is_some()
    }

    pub fn len(&self) -> usize {
        let mut sessions = self
            .sessions
            .lock()
            .expect("pairing manager mutex poisoned");
        self.prune_expired(&mut sessions);
        sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for PairingManager {
    fn default() -> Self {
        Self::new()
    }
}
