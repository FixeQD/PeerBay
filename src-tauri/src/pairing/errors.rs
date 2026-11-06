use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PairingExchangeError {
    InvalidPairingId,
    InvalidDeviceId,
    InvalidCertificateFingerprint,
    InvalidCommitment,
    InvalidNonce,
    InvalidProtocolVersions,
    DuplicateSession,
    StateMismatch { expected: &'static str, got: &'static str },
    CommitmentMismatch,
    NonceRevealMismatch,
    ProtocolVersionMismatch,
    Expired,
    Cancelled,
    AlreadyCompleted,
    MissingPeerNonce,
    IncompleteExchange,
    TooManySessions,
    RandomFailure,
    SasCodeMismatch,
    UserDenied,
    InvalidSasCodeLifetime,
    MissingPeerIdentity,
    InvalidSessionToken,
    TrustPersistFailed,
    TokenExpired,
}

impl Display for PairingExchangeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPairingId => write!(formatter, "pairing id is invalid"),
            Self::InvalidDeviceId => write!(formatter, "device id is invalid"),
            Self::InvalidCertificateFingerprint => {
                write!(formatter, "certificate fingerprint is invalid")
            }
            Self::InvalidCommitment => write!(formatter, "commitment is not canonical lowercase hex"),
            Self::InvalidNonce => write!(formatter, "nonce is not canonical lowercase hex"),
            Self::InvalidProtocolVersions => write!(formatter, "protocol versions are invalid"),
            Self::DuplicateSession => write!(formatter, "pairing session already exists"),
            Self::StateMismatch { expected, got } => write!(
                formatter,
                "pairing state mismatch: expected {expected}, got {got}"
            ),
            Self::CommitmentMismatch => write!(formatter, "nonce commitment verification failed"),
            Self::NonceRevealMismatch => write!(formatter, "revealed nonce does not match commitment"),
            Self::ProtocolVersionMismatch => write!(formatter, "no common protocol version"),
            Self::Expired => write!(formatter, "pairing exchange expired"),
            Self::Cancelled => write!(formatter, "pairing exchange cancelled"),
            Self::AlreadyCompleted => write!(formatter, "pairing exchange already completed"),
            Self::MissingPeerNonce => write!(formatter, "peer nonce has not been received"),
            Self::IncompleteExchange => write!(formatter, "pairing exchange is not complete"),
            Self::TooManySessions => write!(formatter, "too many concurrent pairing sessions"),
            Self::RandomFailure => write!(formatter, "random nonce generation failed"),
            Self::SasCodeMismatch => write!(formatter, "pairing SAS code does not match"),
            Self::UserDenied => write!(formatter, "pairing was denied by the user"),
            Self::InvalidSasCodeLifetime => {
                write!(formatter, "pairing SAS code lifetime must be greater than zero")
            }
            Self::MissingPeerIdentity => {
                write!(formatter, "peer identity is missing from the pairing exchange")
            }
            Self::InvalidSessionToken => {
                write!(formatter, "pairing session token is invalid")
            }
            Self::TrustPersistFailed => {
                write!(formatter, "pairing trust record could not be persisted")
            }
            Self::TokenExpired => write!(formatter, "pairing session token has expired"),
        }
    }
}

impl std::error::Error for PairingExchangeError {}

pub type PairingStateMachineError = PairingExchangeError;
