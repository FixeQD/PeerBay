use crate::pairing::PairingExchangeError;
use crate::protocol::pairing::{PairingCommit, PairingStart};
use super::crypto::*;
use super::validation::*;
use super::types::*;
use super::PairingExchange;

use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

impl PairingExchange {
    pub fn as_initiator(
        pairing_id: String,
        local_device_id: String,
        local_fingerprint: String,
        local_versions: Vec<u16>,
        timeout: Duration,
    ) -> Result<Self, PairingExchangeError> {
        Self::validate_inputs(&pairing_id, &local_device_id, &local_fingerprint, &local_versions)?;
        let nonce = generate_nonce()?;
        let commitment = hash_nonce(
            &nonce,
            &pairing_id,
            &local_fingerprint,
            "initiator",
        );
        Ok(Self {
            pairing_id,
            role: PairingRole::Initiator,
            local_device_id,
            local_fingerprint,
            local_versions,
            local_nonce: Zeroizing::new(nonce),
            local_commitment: commitment,
            peer_device_id: None,
            peer_fingerprint: None,
            peer_versions: Vec::new(),
            peer_commitment: None,
            peer_nonce: None,
            state: PairingExchangeState::Started,
            created_at: Instant::now(),
            timeout: if timeout.is_zero() {
                Duration::from_secs(60)
            } else {
                timeout
            },
            invalidated: false,
        })
    }

    pub fn from_pairing_start(
        start: &PairingStart,
        local_device_id: String,
        local_fingerprint: String,
        local_versions: Vec<u16>,
        timeout: Duration,
    ) -> Result<(Self, PairingCommit), PairingExchangeError> {
        start.validate().map_err(|_| PairingExchangeError::InvalidPairingId)?;
        validate_device_id(&local_device_id)?;
        validate_fingerprint_hex(&local_fingerprint)?;
        validate_protocol_versions(&local_versions)?;
        parse_pairing_id(&start.pairing_id)?;
        validate_device_id(&start.device_id)?;
        validate_fingerprint_hex(&start.certificate_fingerprint)?;
        validate_protocol_versions(&start.protocol_versions)?;
        if let Some(commitment) = Some(&start.nonce_commitment)
            && !is_lower_hex(commitment, 64)
        {
            return Err(PairingExchangeError::InvalidCommitment);
        }

        let common = start
            .protocol_versions
            .iter()
            .copied()
            .any(|version| local_versions.contains(&version));
        if !common {
            return Err(PairingExchangeError::ProtocolVersionMismatch);
        }

        let nonce = generate_nonce()?;
        let commitment = hash_nonce(
            &nonce,
            &start.pairing_id,
            &local_fingerprint,
            "responder",
        );
        let exchange = Self {
            pairing_id: start.pairing_id.clone(),
            role: PairingRole::Responder,
            local_device_id,
            local_fingerprint: local_fingerprint.clone(),
            local_versions,
            local_nonce: Zeroizing::new(nonce),
            local_commitment: commitment.clone(),
            peer_device_id: Some(start.device_id.clone()),
            peer_fingerprint: Some(start.certificate_fingerprint.clone()),
            peer_versions: start.protocol_versions.clone(),
            peer_commitment: Some(start.nonce_commitment.clone()),
            peer_nonce: None,
            state: PairingExchangeState::Committed,
            created_at: Instant::now(),
            timeout: if timeout.is_zero() {
                Duration::from_secs(60)
            } else {
                timeout
            },
            invalidated: false,
        };

        let commit = PairingCommit::new_with_certificate(
            exchange.pairing_id.clone(),
            commitment,
            exchange.local_fingerprint.clone(),
        )
        .map_err(|_| PairingExchangeError::InvalidCommitment)?;
        Ok((exchange, commit))
    }
}
