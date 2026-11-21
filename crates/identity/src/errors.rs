use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub enum DeviceIdentityError {
    InvalidDeviceId,
    InvalidDeviceIdFormat,
    NilDeviceId,
    EmptyDisplayName,
    DisplayNameTooLong { length: usize, max: usize },
    DisplayNameUnexpectedWhitespace,
    DisplayNameControlCharacter,
    DisplayNameFormatCharacter,
    DisplayNameLineSeparator,
}

impl Display for DeviceIdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDeviceId => write!(formatter, "device ID must not be empty"),
            Self::InvalidDeviceIdFormat => {
                write!(formatter, "device ID must be a canonical lowercase UUID")
            }
            Self::NilDeviceId => write!(formatter, "device ID must not be the nil UUID"),
            Self::EmptyDisplayName => write!(formatter, "device display name must not be empty"),
            Self::DisplayNameTooLong { length, max } => write!(
                formatter,
                "device display name is too long: {length} bytes, limit is {max}"
            ),
            Self::DisplayNameUnexpectedWhitespace => write!(
                formatter,
                "device display name must not have surrounding whitespace"
            ),
            Self::DisplayNameControlCharacter => {
                write!(
                    formatter,
                    "device display name contains a control character"
                )
            }
            Self::DisplayNameFormatCharacter => {
                write!(
                    formatter,
                    "device display name contains a Unicode format character"
                )
            }
            Self::DisplayNameLineSeparator => {
                write!(
                    formatter,
                    "device display name contains a Unicode line separator"
                )
            }
        }
    }
}

impl std::error::Error for DeviceIdentityError {}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityKeyPairError {
    PublicKeyMismatch,
}

impl Display for IdentityKeyPairError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublicKeyMismatch => {
                write!(
                    formatter,
                    "identity keypair public key does not match private key"
                )
            }
        }
    }
}

impl std::error::Error for IdentityKeyPairError {}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityKeyStoreError {
    MissingKeyPair,
}

impl Display for IdentityKeyStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKeyPair => write!(formatter, "identity keypair is not available"),
        }
    }
}

impl std::error::Error for IdentityKeyStoreError {}

#[derive(Debug, PartialEq, Eq)]
pub enum TransportCertificateError {
    GenerationFailed { detail: String },
    EmptyCertificate,
    InvalidPublicKeyLength { length: usize },
    FingerprintMismatch,
}

impl Display for TransportCertificateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenerationFailed { detail } => {
                write!(
                    formatter,
                    "transport certificate generation failed: {detail}"
                )
            }
            Self::EmptyCertificate => write!(formatter, "transport certificate is empty"),
            Self::InvalidPublicKeyLength { length } => write!(
                formatter,
                "transport certificate public key has invalid length: {length}"
            ),
            Self::FingerprintMismatch => {
                write!(
                    formatter,
                    "transport certificate fingerprint does not match DER"
                )
            }
        }
    }
}

impl std::error::Error for TransportCertificateError {}
