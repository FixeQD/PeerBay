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
pub fn start_message(&mut self) -> Result<PairingStart, PairingExchangeError> {
        self.ensure_active()?;
        if self.role != PairingRole::Initiator {
            return Err(PairingExchangeError::StateMismatch {
                expected: "initiator",
                got: self.role.as_str(),
            });
        }
        if self.state != PairingExchangeState::Started {
            return Err(PairingExchangeError::StateMismatch {
                expected: "started",
                got: self.state.as_str(),
            });
        }
        PairingStart::new(
            self.pairing_id.clone(),
            self.local_device_id.clone(),
            self.local_fingerprint.clone(),
            self.local_versions.clone(),
            self.local_commitment.clone(),
        )
        .map_err(|_| PairingExchangeError::InvalidPairingId)
    }

    pub fn apply_commit(&mut self, commit: &PairingCommit) -> Result<(), PairingExchangeError> {
        self.ensure_active()?;
        if self.role != PairingRole::Initiator {
            return Err(PairingExchangeError::StateMismatch {
                expected: "initiator",
                got: self.role.as_str(),
            });
        }
        if self.state != PairingExchangeState::Started {
            return Err(PairingExchangeError::StateMismatch {
                expected: "started",
                got: self.state.as_str(),
            });
        }
        if commit.pairing_id != self.pairing_id {
            return Err(PairingExchangeError::InvalidPairingId);
        }
        if !is_lower_hex(&commit.nonce_commitment, 64) {
            return Err(PairingExchangeError::InvalidCommitment);
        }
        if let Some(fingerprint) = &commit.certificate_fingerprint {
            validate_fingerprint_hex(fingerprint)?;
            self.peer_fingerprint = Some(fingerprint.clone());
        }
        self.peer_commitment = Some(commit.nonce_commitment.clone());
        self.state = PairingExchangeState::Committed;
        Ok(())
    }

    pub fn apply_start(&mut self, start: &PairingStart) -> Result<PairingCommit, PairingExchangeError> {
        self.ensure_active()?;
        if self.role != PairingRole::Responder {
            return Err(PairingExchangeError::StateMismatch {
                expected: "responder",
                got: self.role.as_str(),
            });
        }
        if self.state != PairingExchangeState::Idle {
            return Err(PairingExchangeError::StateMismatch {
                expected: "idle",
                got: self.state.as_str(),
            });
        }
        let result = Self::from_pairing_start(
            start,
            self.local_device_id.clone(),
            self.local_fingerprint.clone(),
            self.local_versions.clone(),
            self.timeout,
        )?;
        *self = result.0;
        Ok(result.1)
    }
}
