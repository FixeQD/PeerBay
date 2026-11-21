use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    EmptyChanges,
    EmptySetResponse,
    DuplicateFeature {
        field: &'static str,
        feature: String,
    },
    DuplicateIdentifier {
        field: &'static str,
        value: String,
    },
    RestrictionsRequireLimitedState {
        feature: String,
    },
    LimitedStateRequiresRestriction {
        feature: String,
    },
    ExpiryNotAllowedForUnset {
        feature: String,
    },
    ZeroMaxBytes {
        feature: String,
    },
    ZeroExpiry {
        feature: String,
    },
    UnexpectedWhitespace {
        field: &'static str,
        index: Option<usize>,
    },
    ControlCharacter {
        field: &'static str,
        index: Option<usize>,
    },
    InvalidIdentifierCharacter {
        field: &'static str,
        index: Option<usize>,
        character: char,
    },
}

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChanges => write!(formatter, "policy.set must contain at least one change"),
            Self::EmptySetResponse => write!(
                formatter,
                "policy.set response must contain an applied or rejected feature"
            ),
            Self::DuplicateFeature { field, feature } => {
                write!(
                    formatter,
                    "policy {field} contains duplicate feature {feature}"
                )
            }
            Self::DuplicateIdentifier { field, value } => {
                write!(
                    formatter,
                    "policy {field} contains duplicate identifier {value}"
                )
            }
            Self::RestrictionsRequireLimitedState { feature } => write!(
                formatter,
                "policy {feature} must use allow_limited when restrictions are present"
            ),
            Self::LimitedStateRequiresRestriction { feature } => write!(
                formatter,
                "allow_limited policy {feature} must declare a restriction"
            ),
            Self::ExpiryNotAllowedForUnset { feature } => write!(
                formatter,
                "unset policy {feature} must not declare an expiry"
            ),
            Self::ZeroMaxBytes { feature } => {
                write!(
                    formatter,
                    "policy {feature} max_bytes must be greater than zero"
                )
            }
            Self::ZeroExpiry { feature } => {
                write!(
                    formatter,
                    "policy {feature} expiry must be greater than zero"
                )
            }
            Self::UnexpectedWhitespace { field, index } => write!(
                formatter,
                "policy field {field}{} has unexpected surrounding whitespace",
                format_index(*index)
            ),
            Self::ControlCharacter { field, index } => write!(
                formatter,
                "policy field {field}{} contains a control character",
                format_index(*index)
            ),
            Self::InvalidIdentifierCharacter {
                field,
                index,
                character,
            } => write!(
                formatter,
                "policy field {field}{} contains invalid identifier character {character:?}",
                format_index(*index)
            ),
        }
    }
}

fn format_index(index: Option<usize>) -> String {
    index.map_or_else(String::new, |index| format!("[{index}]"))
}

impl std::error::Error for PolicyError {}
