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
pub fn reveal(&mut self) -> Result<ProtocolNonce, PairingExchangeError> {
        self.ensure_active()?;
        if !matches!(self.state, PairingExchangeState::Committed) {
            return Err(PairingExchangeError::StateMismatch {
                expected: "committed",
                got: self.state.as_str(),
            });
        }
        let reveal = ProtocolNonce::new(self.pairing_id.clone(), hex_encode(&self.local_nonce))
            .map_err(|_| PairingExchangeError::InvalidNonce)?;
        self.state = PairingExchangeState::Revealing;
        Ok(reveal)
    }

    pub fn apply_reveal(&mut self, reveal: &PairingReveal) -> Result<(), PairingExchangeError> {
        self.ensure_active()?;
        if !matches!(self.state, PairingExchangeState::Committed | PairingExchangeState::Revealing) {
            return Err(PairingExchangeError::StateMismatch {
                expected: "committed",
                got: self.state.as_str(),
            });
        }
        if reveal.pairing_id != self.pairing_id {
            return Err(PairingExchangeError::InvalidPairingId);
        }
        if !is_lower_hex(&reveal.nonce, 64) {
            return Err(PairingExchangeError::InvalidNonce);
        }

        let expected_peer_commitment = self
            .peer_commitment
            .clone()
            .ok_or(PairingExchangeError::IncompleteExchange)?;
        let computed = hash_nonce(
            &hex_decode(&reveal.nonce)?,
            self.pairing_id.as_str(),
            self.peer_fingerprint.as_deref().unwrap_or_default(),
            if self.role == PairingRole::Initiator {
                "responder"
            } else {
                "initiator"
            },
        );
        if computed != expected_peer_commitment {
            self.state = PairingExchangeState::Rejected;
            self.invalidate_secrets();
            return Err(PairingExchangeError::CommitmentMismatch);
        }

        self.peer_nonce = Some(Zeroizing::new(hex_decode(&reveal.nonce)?));
        self.state = PairingExchangeState::Revealed;
        Ok(())
    }

    pub fn apply_nonce(&mut self, nonce: &ProtocolNonce) -> Result<(), PairingExchangeError> {
        let reveal = PairingReveal::new(nonce.pairing_id.clone(), nonce.nonce.clone())
            .map_err(|_| PairingExchangeError::InvalidNonce)?;
        self.apply_reveal(&reveal)
    }
}
