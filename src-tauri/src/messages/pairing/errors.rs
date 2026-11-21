use std::fmt::{Display, Formatter};

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
