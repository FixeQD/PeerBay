use std::fmt::{Display, Formatter};

use super::types::PrivilegeProvider;

#[derive(Debug, PartialEq, Eq)]
pub enum PrivilegeError {
    DuplicateBackend {
        provider: PrivilegeProvider,
    },
    DuplicateValue {
        field: &'static str,
        value: String,
    },
    UnexpectedWhitespace {
        field: &'static str,
    },
    ControlCharacter {
        field: &'static str,
    },
    InvalidIdentifierCharacter {
        field: &'static str,
    },
    ZeroTimestamp {
        field: &'static str,
    },
    TimestampOrder {
        earlier_field: &'static str,
        later_field: &'static str,
    },
    ExpiryNotAfterCheck {
        field: &'static str,
        checked_at_ms: u64,
        expires_at_ms: u64,
    },
    MissingNextAction,
    UnexpectedNextAction,
    DecisionRequiresUserAction,
    ProofProviderMismatch,
    ProofAuthorityMismatch,
    AdbTransportRequiresAdbProvider,
}

impl Display for PrivilegeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateBackend { provider } => {
                write!(
                    formatter,
                    "privilege snapshot contains duplicate provider {provider:?}"
                )
            }
            Self::DuplicateValue { field, value } => {
                write!(
                    formatter,
                    "privilege field {field} contains duplicate value {value}"
                )
            }
            Self::UnexpectedWhitespace { field } => {
                write!(
                    formatter,
                    "privilege field {field} has unexpected surrounding whitespace"
                )
            }
            Self::ControlCharacter { field } => {
                write!(
                    formatter,
                    "privilege field {field} contains a control character"
                )
            }
            Self::InvalidIdentifierCharacter { field } => {
                write!(
                    formatter,
                    "privilege field {field} contains an invalid identifier character"
                )
            }
            Self::ZeroTimestamp { field } => {
                write!(
                    formatter,
                    "privilege timestamp {field} must be greater than zero"
                )
            }
            Self::TimestampOrder {
                earlier_field,
                later_field,
            } => write!(
                formatter,
                "privilege timestamp {later_field} must not precede {earlier_field}"
            ),
            Self::ExpiryNotAfterCheck {
                field,
                checked_at_ms,
                expires_at_ms,
            } => write!(
                formatter,
                "privilege expiry {field} ({expires_at_ms}) must be after the check ({checked_at_ms})"
            ),
            Self::MissingNextAction => {
                write!(
                    formatter,
                    "a privilege result requiring user action must provide next_action"
                )
            }
            Self::UnexpectedNextAction => write!(
                formatter,
                "a privilege result without required user action must not provide next_action"
            ),
            Self::DecisionRequiresUserAction => write!(
                formatter,
                "needs_user_action decision must set requires_user_action"
            ),
            Self::ProofProviderMismatch => {
                write!(
                    formatter,
                    "privilege proof provider does not match the reported provider"
                )
            }
            Self::ProofAuthorityMismatch => {
                write!(
                    formatter,
                    "privilege proof authority does not match the reported authority"
                )
            }
            Self::AdbTransportRequiresAdbProvider => write!(
                formatter,
                "adb transport metadata requires a USB ADB or Wireless ADB provider"
            ),
        }
    }
}

impl std::error::Error for PrivilegeError {}
