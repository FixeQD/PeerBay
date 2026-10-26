use std::fmt::{Display, Formatter};

const MAX_TRANSPORT_IDENTIFIER_LENGTH: usize = 4 * 1024;

pub(super) fn validate_transport_string(field: &'static str, value: &str) -> eros::Result<()> {
    if value.trim().is_empty() {
        return Err(eros::error!(TransportError::EmptyField { field }));
    }
    if value != value.trim() {
        return Err(eros::error!(TransportError::UnexpectedWhitespace { field }));
    }
    if value.len() > MAX_TRANSPORT_IDENTIFIER_LENGTH {
        return Err(eros::error!(TransportError::FieldTooLong {
            field,
            length: value.len(),
            max: MAX_TRANSPORT_IDENTIFIER_LENGTH,
        }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(TransportError::ControlCharacter { field }));
    }
    Ok(())
}

pub(super) fn validate_transport_identifier(field: &'static str, value: &str) -> eros::Result<()> {
    validate_transport_string(field, value)?;
    if value.chars().any(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-' | ':')
    }) {
        return Err(eros::error!(TransportError::InvalidIdentifierCharacter {
            field
        }));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    EmptyField {
        field: &'static str,
    },
    FieldTooLong {
        field: &'static str,
        length: usize,
        max: usize,
    },
    ControlCharacter {
        field: &'static str,
    },
    UnexpectedWhitespace {
        field: &'static str,
    },
    InvalidIdentifierCharacter {
        field: &'static str,
    },
}

impl Display for TransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField { field } => write!(formatter, "transport {field} must not be empty"),
            Self::FieldTooLong { field, length, max } => write!(
                formatter,
                "transport {field} is too long: {length} bytes, limit is {max}"
            ),
            Self::ControlCharacter { field } => {
                write!(formatter, "transport {field} contains a control character")
            }
            Self::UnexpectedWhitespace { field } => {
                write!(
                    formatter,
                    "transport {field} has unexpected surrounding whitespace"
                )
            }
            Self::InvalidIdentifierCharacter { field } => write!(
                formatter,
                "transport {field} contains an invalid identifier character"
            ),
        }
    }
}

impl std::error::Error for TransportError {}
