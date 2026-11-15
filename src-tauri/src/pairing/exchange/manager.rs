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
            .map_err(|_| PairingExchangeError::SessionLockPoisoned)?;
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
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.prune_expired(&mut sessions);
        sessions.get(pairing_id).cloned()
    }

    pub fn remove(&self, pairing_id: &str) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sessions.remove(pairing_id).is_some()
    }

    pub fn len(&self) -> usize {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const FINGERPRINT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn poisoned_manager() -> PairingManager {
        let manager = PairingManager::new();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = manager.sessions.lock().unwrap();
            panic!("poison the pairing manager mutex");
        }));
        manager
    }

    fn fresh_exchange(pairing_id: &str) -> PairingExchange {
        PairingExchange::as_initiator(
            pairing_id.to_owned(),
            DEVICE_ID.to_owned(),
            FINGERPRINT.to_owned(),
            vec![1],
            Duration::from_secs(60),
        )
        .unwrap()
    }

    #[test]
    fn poisoned_manager_lock_fails_insert_and_reads_recover() {
        let manager = poisoned_manager();
        assert_eq!(
            manager.insert(fresh_exchange("pair-lock-2")).err(),
            Some(PairingExchangeError::SessionLockPoisoned)
        );
        assert_eq!(manager.len(), 0);
        assert!(manager.get("pair-lock-2").is_none());
        assert!(!manager.remove("pair-lock-2"));
        assert!(manager.is_empty());
    }

    #[test]
    fn manager_reads_recover_after_poisoned_lock() {
        let manager = poisoned_manager();
        assert_eq!(
            manager
                .begin_initiator(
                    "pair-lock-3".to_owned(),
                    DEVICE_ID.to_owned(),
                    FINGERPRINT.to_owned(),
                    vec![1],
                    Duration::from_secs(60),
                )
                .err(),
            Some(PairingExchangeError::SessionLockPoisoned)
        );
        assert_eq!(manager.len(), 0);
        assert!(manager.get("pair-lock-3").is_none());
        assert!(manager.is_empty());
    }
}
