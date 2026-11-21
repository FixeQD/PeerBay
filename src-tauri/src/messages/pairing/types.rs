use serde::{Deserialize, Serialize};

use super::errors::PairingError;
use super::validation::{
    HEX_256_LENGTH, validate_expiry, validate_hex_256, validate_identifier, validate_pairing_id,
    validate_protocol_versions, validate_sas_code,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingStart {
    pub pairing_id: String,
    pub device_id: String,
    pub certificate_fingerprint: String,
    pub protocol_versions: Vec<u16>,
    pub nonce_commitment: String,
}

impl PairingStart {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pairing_id: impl Into<String>,
        device_id: impl Into<String>,
        certificate_fingerprint: impl Into<String>,
        protocol_versions: Vec<u16>,
        nonce_commitment: impl Into<String>,
    ) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            device_id: device_id.into(),
            certificate_fingerprint: certificate_fingerprint.into(),
            protocol_versions,
            nonce_commitment: nonce_commitment.into(),
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)?;
        validate_identifier("device_id", &self.device_id)?;
        validate_hex_256("certificate_fingerprint", &self.certificate_fingerprint)?;
        validate_protocol_versions(&self.protocol_versions)?;
        validate_hex_256("nonce_commitment", &self.nonce_commitment)
    }
}

/// Responder's public nonce commitment after receiving `pair.start`
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingCommit {
    pub pairing_id: String,
    pub nonce_commitment: String,
    #[serde(default)]
    pub certificate_fingerprint: Option<String>,
}

impl PairingCommit {
    pub fn new(
        pairing_id: impl Into<String>,
        nonce_commitment: impl Into<String>,
    ) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            nonce_commitment: nonce_commitment.into(),
            certificate_fingerprint: None,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn new_with_certificate(
        pairing_id: impl Into<String>,
        nonce_commitment: impl Into<String>,
        certificate_fingerprint: impl Into<String>,
    ) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            nonce_commitment: nonce_commitment.into(),
            certificate_fingerprint: Some(certificate_fingerprint.into()),
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)?;
        validate_hex_256("nonce_commitment", &self.nonce_commitment)?;
        if let Some(fingerprint) = &self.certificate_fingerprint {
            if fingerprint.len() != HEX_256_LENGTH {
                return Err(eros::error!(PairingError::InvalidHexLength {
                    field: "certificate_fingerprint",
                    length: fingerprint.len(),
                    expected: HEX_256_LENGTH,
                }));
            }
            if !fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(eros::error!(PairingError::InvalidHexValue {
                    field: "certificate_fingerprint"
                }));
            }
        }
        Ok(())
    }
}

/// Responder's temporary nonce reveal.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingNonce {
    pub pairing_id: String,
    pub nonce: String,
}

impl PairingNonce {
    pub fn new(pairing_id: impl Into<String>, nonce: impl Into<String>) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            nonce: nonce.into(),
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)?;
        validate_hex_256("nonce", &self.nonce)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingReveal {
    pub pairing_id: String,
    pub nonce: String,
}

impl PairingReveal {
    pub fn new(pairing_id: impl Into<String>, nonce: impl Into<String>) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            nonce: nonce.into(),
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)?;
        validate_hex_256("nonce", &self.nonce)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingCode {
    pub pairing_id: String,
    pub sas_code: String,
    pub expires_at_ms: u64,
}

impl PairingCode {
    pub fn new(
        pairing_id: impl Into<String>,
        sas_code: impl Into<String>,
        expires_at_ms: u64,
    ) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            sas_code: sas_code.into(),
            expires_at_ms,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)?;
        validate_sas_code(&self.sas_code)?;
        validate_expiry(self.expires_at_ms)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingConfirm {
    pub pairing_id: String,
    pub sas_code: Option<String>,
    pub confirmed: bool,
}

impl PairingConfirm {
    pub fn accepted(
        pairing_id: impl Into<String>,
        sas_code: impl Into<String>,
    ) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            sas_code: Some(sas_code.into()),
            confirmed: true,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn denied(pairing_id: impl Into<String>) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            sas_code: None,
            confirmed: false,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)?;

        match (self.confirmed, self.sas_code.as_deref()) {
            (true, Some(code)) => validate_sas_code(code),
            (true, None) => Err(eros::error!(PairingError::MissingSasCode)),
            (false, None) => Ok(()),
            (false, Some(_)) => Err(eros::error!(PairingError::SasCodeOnDeniedConfirmation)),
        }
    }
}

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingAccepted {
    pub pairing_id: String,
    pub session_token: String,
    pub expires_at_ms: u64,
}

impl std::fmt::Debug for PairingAccepted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingAccepted")
            .field("pairing_id", &self.pairing_id)
            .field("session_token", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl PairingAccepted {
    pub fn new(
        pairing_id: impl Into<String>,
        session_token: impl Into<String>,
        expires_at_ms: u64,
    ) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            session_token: session_token.into(),
            expires_at_ms,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)?;
        validate_hex_256("session_token", &self.session_token)?;
        validate_expiry(self.expires_at_ms)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingRejectionReason {
    CodeMismatch,
    FingerprintMismatch,
    InvalidNonce,
    UnsupportedProtocol,
    UserDenied,
    Timeout,
    AlreadyInProgress,
    ProtocolViolation,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingRejected {
    pub pairing_id: String,
    pub reason: PairingRejectionReason,
    pub retryable: bool,
}

impl PairingRejected {
    pub fn new(
        pairing_id: impl Into<String>,
        reason: PairingRejectionReason,
        retryable: bool,
    ) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            reason,
            retryable,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingCancellationReason {
    UserRequested,
    Timeout,
    PeerDisconnected,
    BackendShutdown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingCancelled {
    pub pairing_id: String,
    pub reason: PairingCancellationReason,
}

impl PairingCancelled {
    pub fn new(
        pairing_id: impl Into<String>,
        reason: PairingCancellationReason,
    ) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            reason,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)
    }
}
