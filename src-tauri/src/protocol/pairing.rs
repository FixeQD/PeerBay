#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use super::limits::ProtocolLimits;

const HEX_256_LENGTH: usize = 64;
const SAS_CODE_LENGTH: usize = 6;

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
}

impl PairingCommit {
    pub fn new(
        pairing_id: impl Into<String>,
        nonce_commitment: impl Into<String>,
    ) -> eros::Result<Self> {
        let message = Self {
            pairing_id: pairing_id.into(),
            nonce_commitment: nonce_commitment.into(),
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_pairing_id(&self.pairing_id)?;
        validate_hex_256("nonce_commitment", &self.nonce_commitment)
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PairingAccepted {
    pub pairing_id: String,
    pub session_token: String,
    pub expires_at_ms: u64,
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

fn validate_pairing_id(value: &str) -> eros::Result<()> {
    validate_identifier("pairing_id", value)
}

fn validate_identifier(field: &'static str, value: &str) -> eros::Result<()> {
    let limits = ProtocolLimits::default();
    limits.validate_string(field, value)?;

    if value != value.trim() {
        return Err(eros::error!(PairingError::UnexpectedWhitespace { field }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(PairingError::ControlCharacter { field }));
    }
    if value.chars().any(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-' | ':')
    }) {
        return Err(eros::error!(PairingError::InvalidIdentifierCharacter {
            field
        }));
    }

    Ok(())
}

fn validate_hex_256(field: &'static str, value: &str) -> eros::Result<()> {
    if value.len() != HEX_256_LENGTH {
        return Err(eros::error!(PairingError::InvalidHexLength {
            field,
            length: value.len(),
            expected: HEX_256_LENGTH,
        }));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(eros::error!(PairingError::InvalidHexValue { field }));
    }

    Ok(())
}

fn validate_sas_code(value: &str) -> eros::Result<()> {
    if value.len() != SAS_CODE_LENGTH {
        return Err(eros::error!(PairingError::InvalidSasCodeLength {
            length: value.len(),
            expected: SAS_CODE_LENGTH,
        }));
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(eros::error!(PairingError::InvalidSasCodeValue));
    }

    Ok(())
}

fn validate_expiry(expires_at_ms: u64) -> eros::Result<()> {
    if expires_at_ms == 0 {
        return Err(eros::error!(PairingError::ZeroExpiry));
    }
    Ok(())
}

fn validate_protocol_versions(versions: &[u16]) -> eros::Result<()> {
    let limits = ProtocolLimits::default();
    if versions.is_empty() {
        return Err(eros::error!(PairingError::EmptyProtocolVersions));
    }
    limits.validate_batch("protocol_versions", versions.len())?;

    let mut seen = HashSet::with_capacity(versions.len());
    for version in versions {
        if *version == 0 {
            return Err(eros::error!(PairingError::InvalidProtocolVersion {
                version: *version
            }));
        }
        if !seen.insert(version) {
            return Err(eros::error!(PairingError::DuplicateProtocolVersion {
                version: *version
            }));
        }
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum PairingError {
    EmptyProtocolVersions,
    InvalidProtocolVersion {
        version: u16,
    },
    DuplicateProtocolVersion {
        version: u16,
    },
    InvalidHexLength {
        field: &'static str,
        length: usize,
        expected: usize,
    },
    InvalidHexValue {
        field: &'static str,
    },
    InvalidSasCodeLength {
        length: usize,
        expected: usize,
    },
    InvalidSasCodeValue,
    MissingSasCode,
    SasCodeOnDeniedConfirmation,
    ZeroExpiry,
    UnexpectedWhitespace {
        field: &'static str,
    },
    ControlCharacter {
        field: &'static str,
    },
    InvalidIdentifierCharacter {
        field: &'static str,
    },
}

impl Display for PairingError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyProtocolVersions => {
                write!(
                    formatter,
                    "pairing must advertise at least one protocol version"
                )
            }
            Self::InvalidProtocolVersion { version } => {
                write!(formatter, "pairing protocol version {version} is invalid")
            }
            Self::DuplicateProtocolVersion { version } => {
                write!(
                    formatter,
                    "pairing protocol version {version} is duplicated"
                )
            }
            Self::InvalidHexLength {
                field,
                length,
                expected,
            } => write!(
                formatter,
                "pairing field {field} has {length} hex characters; expected {expected}"
            ),
            Self::InvalidHexValue { field } => {
                write!(
                    formatter,
                    "pairing field {field} is not canonical lowercase hex"
                )
            }
            Self::InvalidSasCodeLength { length, expected } => write!(
                formatter,
                "pairing SAS code has {length} characters; expected {expected}"
            ),
            Self::InvalidSasCodeValue => {
                write!(formatter, "pairing SAS code must contain ASCII digits only")
            }
            Self::MissingSasCode => {
                write!(formatter, "confirmed pairing must include the SAS code")
            }
            Self::SasCodeOnDeniedConfirmation => write!(
                formatter,
                "denied pairing confirmation must not include the SAS code"
            ),
            Self::ZeroExpiry => write!(formatter, "pairing expiry must be greater than zero"),
            Self::UnexpectedWhitespace { field } => {
                write!(
                    formatter,
                    "pairing field {field} has unexpected surrounding whitespace"
                )
            }
            Self::ControlCharacter { field } => {
                write!(
                    formatter,
                    "pairing field {field} contains a control character"
                )
            }
            Self::InvalidIdentifierCharacter { field } => write!(
                formatter,
                "pairing field {field} contains an invalid identifier character"
            ),
        }
    }
}

impl std::error::Error for PairingError {}
