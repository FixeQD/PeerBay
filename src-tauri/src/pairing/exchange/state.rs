use crate::pairing::PairingExchangeError;
use crate::protocol::pairing::{PairingCommit, PairingNonce as ProtocolNonce, PairingReveal, PairingStart};
use super::crypto::*;
use super::validation::*;
use super::types::*;
use super::PairingExchange;

use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

impl PairingExchange {
pub fn sas_code(&mut self) -> Result<PairingSas, PairingExchangeError> {
        self.ensure_active()?;
        if self.state != PairingExchangeState::Revealed {
            return Err(PairingExchangeError::StateMismatch {
                expected: "revealed",
                got: self.state.as_str(),
            });
        }
        let peer_nonce = self.peer_nonce.as_ref().ok_or(PairingExchangeError::MissingPeerNonce)?;
        let (initiator_nonce, responder_nonce, initiator_fingerprint, responder_fingerprint) =
            if self.role == PairingRole::Initiator {
                (
                    &self.local_nonce,
                    peer_nonce,
                    self.local_fingerprint.clone(),
                    self.peer_fingerprint.clone().unwrap_or_default(),
                )
            } else {
                (
                    peer_nonce,
                    &self.local_nonce,
                    self.peer_fingerprint.clone().unwrap_or_default(),
                    self.local_fingerprint.clone(),
                )
            };

        let mut hasher = Sha256::new();
        hasher.update(initiator_fingerprint.as_bytes());
        hasher.update(responder_fingerprint.as_bytes());
        hasher.update(hex_encode(initiator_nonce));
        hasher.update(hex_encode(responder_nonce));
        let digest = hasher.finalize();
        let numeric = u64::from_be_bytes(digest[0..8].try_into().unwrap_or([0; 8]));
        let code = format!("{:06}", numeric % 1_000_000);

        Ok(PairingSas {
            code,
            initiator_nonce_hex: hex_encode(initiator_nonce),
            responder_nonce_hex: hex_encode(responder_nonce),
        })
    }

    pub fn role(&self) -> PairingRole {
        self.role
    }

    pub fn state(&self) -> PairingExchangeState {
        self.state
    }

    pub fn pairing_id(&self) -> &str {
        &self.pairing_id
    }

    pub fn local_commitment(&self) -> &str {
        &self.local_commitment
    }

    pub fn peer_commitment(&self) -> Option<&str> {
        self.peer_commitment.as_deref()
    }

    pub fn is_expired(&self) -> bool {
        self.state == PairingExchangeState::TimedOut
            || self.state == PairingExchangeState::Cancelled
            || self.created_at.elapsed() >= self.timeout
    }

    pub fn expire_if_timed_out(&mut self) -> bool {
        if matches!(
            self.state,
            PairingExchangeState::Completed
                | PairingExchangeState::Rejected
                | PairingExchangeState::Cancelled
                | PairingExchangeState::TimedOut
        ) {
            return false;
        }
        if self.created_at.elapsed() >= self.timeout {
            self.state = PairingExchangeState::TimedOut;
            self.invalidate_secrets();
            true
        } else {
            false
        }
    }

    pub fn cancel(&mut self) {
        if !matches!(self.state, PairingExchangeState::Completed | PairingExchangeState::Cancelled) {
            self.state = PairingExchangeState::Cancelled;
            self.invalidate_secrets();
        }
    }

    pub fn invalidate_secrets(&mut self) {
        self.local_nonce.zeroize();
        self.local_nonce.clear();
        if let Some(nonce) = &mut self.peer_nonce {
            nonce.zeroize();
            nonce.clear();
        }
        self.peer_nonce = None;
        self.invalidated = true;
    }

    pub(crate) fn ensure_active(&mut self) -> Result<(), PairingExchangeError> {
        match self.state {
            PairingExchangeState::Completed => Err(PairingExchangeError::AlreadyCompleted),
            PairingExchangeState::Cancelled => Err(PairingExchangeError::Cancelled),
            PairingExchangeState::TimedOut => Err(PairingExchangeError::Expired),
            PairingExchangeState::Rejected => Err(PairingExchangeError::CommitmentMismatch),
            _ => {
                if self.created_at.elapsed() >= self.timeout {
                    self.state = PairingExchangeState::TimedOut;
                    self.invalidate_secrets();
                    Err(PairingExchangeError::Expired)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn validate_inputs(
        pairing_id: &str,
        device_id: &str,
        fingerprint: &str,
        versions: &[u16],
    ) -> Result<(), PairingExchangeError> {
        parse_pairing_id(pairing_id)?;
        validate_device_id(device_id)?;
        validate_fingerprint(fingerprint)?;
        validate_protocol_versions(versions)?;
        Ok(())
    }
}
