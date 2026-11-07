use super::PairingExchange;
use super::crypto::*;
use super::trust::SESSION_TOKEN_LIFETIME_MS;
use super::trust::*;
use super::types::*;
use super::validation::*;
use crate::pairing::PairingExchangeError;
use crate::protocol::pairing::{PairingAccepted, PairingCode, PairingConfirm};
use crate::storage::PeerTrustStore;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

impl PairingExchange {
    pub fn sas_code(&mut self) -> Result<PairingSas, PairingExchangeError> {
        self.ensure_active()?;
        if self.state != PairingExchangeState::Revealed {
            return Err(PairingExchangeError::StateMismatch {
                expected: "revealed",
                got: self.state.as_str(),
            });
        }
        let peer_nonce = self
            .peer_nonce
            .as_ref()
            .ok_or(PairingExchangeError::MissingPeerNonce)?;
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

    /// Builds the `pair.code` message carrying the locally computed SAS code
    pub fn emit_pairing_code(
        &mut self,
        code_lifetime_ms: u64,
    ) -> Result<PairingCode, PairingExchangeError> {
        if code_lifetime_ms == 0 {
            return Err(PairingExchangeError::InvalidSasCodeLifetime);
        }
        let sas = self.sas_code()?;
        let expires_at_ms = now_ms().saturating_add(code_lifetime_ms);
        self.code_expires_at_ms = expires_at_ms;
        // Pairing code validation cannot fail here, the pairing id, the SAS code and the expiry were all validated before this point
        Ok(
            PairingCode::new(self.pairing_id.clone(), sas.code, expires_at_ms)
                .expect("pairing code construction is infallible after validation"),
        )
    }

    /// Records the expiry of an issued pairing code propagated to this peer
    pub fn apply_pairing_code(
        &mut self,
        code: &crate::protocol::pairing::PairingCode,
    ) -> Result<(), PairingExchangeError> {
        if code.pairing_id != self.pairing_id {
            return Err(PairingExchangeError::InvalidPairingId);
        }
        code.validate()
            .map_err(|_| PairingExchangeError::InvalidSasCodeLifetime)?;
        if now_ms() > code.expires_at_ms {
            return Err(PairingExchangeError::Expired);
        }
        self.code_expires_at_ms = code.expires_at_ms;
        Ok(())
    }

    pub fn verify_pairing_confirm(
        &mut self,
        confirm: &PairingConfirm,
    ) -> Result<(), PairingExchangeError> {
        self.ensure_active()?;
        if self.state != PairingExchangeState::Revealed {
            return Err(PairingExchangeError::StateMismatch {
                expected: "revealed",
                got: self.state.as_str(),
            });
        }
        if self.code_expires_at_ms != 0 && now_ms() > self.code_expires_at_ms {
            return Err(PairingExchangeError::Expired);
        }
        if confirm.pairing_id != self.pairing_id {
            return Err(PairingExchangeError::InvalidPairingId);
        }
        if !confirm.confirmed {
            self.state = PairingExchangeState::Rejected;
            self.invalidate_secrets();
            return Err(PairingExchangeError::UserDenied);
        }
        let expected_code = self.sas_code()?.code;
        let provided_code = confirm
            .sas_code
            .as_deref()
            .ok_or(PairingExchangeError::MissingPeerNonce)?;
        if provided_code != expected_code {
            self.state = PairingExchangeState::Rejected;
            self.invalidate_secrets();
            return Err(PairingExchangeError::SasCodeMismatch);
        }
        self.state = PairingExchangeState::Confirmed;
        self.invalidate_secrets();
        Ok(())
    }

    pub fn accept(
        &mut self,
        trust_store: &PeerTrustStore,
        display_name: impl Into<String>,
        platform: impl Into<String>,
    ) -> Result<PairingAccepted, PairingExchangeError> {
        if self.state != PairingExchangeState::Confirmed {
            return Err(PairingExchangeError::StateMismatch {
                expected: "confirmed",
                got: self.state.as_str(),
            });
        }

        let peer_device_id = self
            .peer_device_id
            .as_ref()
            .ok_or(PairingExchangeError::MissingPeerIdentity)?
            .clone();
        let peer_fingerprint = self
            .peer_fingerprint
            .as_ref()
            .ok_or(PairingExchangeError::MissingPeerIdentity)?
            .clone();

        let mut record =
            build_peer_record(&peer_device_id, &peer_fingerprint, display_name, platform)?;
        let token_hex = issue_session_token(&mut record)?;

        trust_store
            .save(&peer_device_id, &record)
            .map_err(|_| PairingExchangeError::TrustPersistFailed)?;

        let expires_at_ms = now_ms().saturating_add(SESSION_TOKEN_LIFETIME_MS);
        let accepted = PairingAccepted::new(self.pairing_id.clone(), token_hex, expires_at_ms)
            .map_err(|_| PairingExchangeError::InvalidSessionToken)?;

        self.state = PairingExchangeState::SessionTokenIssued;
        Ok(accepted)
    }

    pub fn apply_accepted(
        &mut self,
        trust_store: &PeerTrustStore,
        peer_device_id: impl Into<String>,
        accepted: &PairingAccepted,
        display_name: impl Into<String>,
        platform: impl Into<String>,
    ) -> Result<(), PairingExchangeError> {
        if self.state != PairingExchangeState::Confirmed {

            return Err(PairingExchangeError::StateMismatch {
                expected: "confirmed",
                got: self.state.as_str(),
            });
        }
        if accepted.pairing_id != self.pairing_id {
            return Err(PairingExchangeError::InvalidPairingId);
        }
        accepted
            .validate()
            .map_err(|_| PairingExchangeError::InvalidSessionToken)?;
        if accepted.expires_at_ms <= now_ms() {
            return Err(PairingExchangeError::TokenExpired);
        }
        if accepted.expires_at_ms > now_ms().saturating_add(SESSION_TOKEN_LIFETIME_MS * 2) {
            return Err(PairingExchangeError::TokenExpired);
        }

        let peer_device_id = peer_device_id.into();
        let peer_fingerprint = self
            .peer_fingerprint
            .as_ref()
            .ok_or(PairingExchangeError::MissingPeerIdentity)?
            .clone();

        let mut record =
            build_peer_record(&peer_device_id, &peer_fingerprint, display_name, platform)?;
        record.pairing_token_hash = hash_presented_token(&accepted.session_token)?;

        trust_store
            .save(&peer_device_id, &record)
            .map_err(|_| PairingExchangeError::TrustPersistFailed)?;

        self.state = PairingExchangeState::SessionTokenIssued;
        Ok(())
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
        if matches!(
            self.state,
            PairingExchangeState::Confirmed
                | PairingExchangeState::SessionTokenIssued
                | PairingExchangeState::Completed
                | PairingExchangeState::Rejected
        ) {
            return false;
        }
        self.state == PairingExchangeState::TimedOut
            || self.state == PairingExchangeState::Cancelled
            || self.created_at.elapsed() >= self.timeout
    }

    pub fn expire_if_timed_out(&mut self) -> bool {
        if matches!(
            self.state,
            PairingExchangeState::Completed
                | PairingExchangeState::Confirmed
                | PairingExchangeState::SessionTokenIssued
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
        if matches!(
            self.state,
            PairingExchangeState::Started
                | PairingExchangeState::Committed
                | PairingExchangeState::Revealing
                | PairingExchangeState::Revealed
                | PairingExchangeState::Confirmed
        ) {
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
        self.code_expires_at_ms = 0;
    }

    pub fn secrets_invalidated(&self) -> bool {
        self.invalidated
    }

    pub(crate) fn ensure_active(&mut self) -> Result<(), PairingExchangeError> {
        match self.state {
            PairingExchangeState::Completed | PairingExchangeState::Confirmed => {
                Err(PairingExchangeError::AlreadyCompleted)
            }
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
