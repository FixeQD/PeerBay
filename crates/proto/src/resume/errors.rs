use std::fmt::{Display, Formatter};

use super::types::SessionChannel;

#[derive(Debug, PartialEq, Eq)]
pub enum ResumeError {
    InvalidKeyLength {
        length: usize,
        expected: usize,
    },
    InvalidKeyValue,
    SameChannelId,
    SameTransport,
    EmptyCursors,
    DuplicateChannel {
        channel: SessionChannel,
    },
    SessionMismatch {
        expected: String,
        received: String,
    },
    ZeroTimestamp {
        field: &'static str,
    },
    ExpiryNotAfterRequest {
        requested_at_ms: u64,
        expires_at_ms: u64,
    },
    AcceptedWithoutResume,
    FallbackExpiryNotAfterResume,
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

impl Display for ResumeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength { length, expected } => write!(
                formatter,
                "resume key has {length} characters; expected {expected}"
            ),
            Self::InvalidKeyValue => {
                write!(formatter, "resume key must be canonical lowercase hex")
            }
            Self::SameChannelId => write!(formatter, "channel migration must change channel ID"),
            Self::SameTransport => write!(formatter, "channel migration must change transport"),
            Self::EmptyCursors => {
                write!(formatter, "resume must include at least one channel cursor")
            }
            Self::DuplicateChannel { channel } => {
                write!(
                    formatter,
                    "resume contains duplicate cursor for {channel:?}"
                )
            }
            Self::SessionMismatch { expected, received } => write!(
                formatter,
                "resume session mismatch: expected {expected}, received {received}"
            ),
            Self::ZeroTimestamp { field } => {
                write!(
                    formatter,
                    "resume timestamp {field} must be greater than zero"
                )
            }
            Self::ExpiryNotAfterRequest {
                requested_at_ms,
                expires_at_ms,
            } => write!(
                formatter,
                "resume expiry {expires_at_ms} must be after request time {requested_at_ms}"
            ),
            Self::AcceptedWithoutResume => {
                write!(formatter, "accepted resume response must set resumed=true")
            }
            Self::FallbackExpiryNotAfterResume => write!(
                formatter,
                "fallback expiry must be after the resumed timestamp"
            ),
            Self::UnexpectedWhitespace { field } => {
                write!(
                    formatter,
                    "resume field {field} has unexpected surrounding whitespace"
                )
            }
            Self::ControlCharacter { field } => {
                write!(
                    formatter,
                    "resume field {field} contains a control character"
                )
            }
            Self::InvalidIdentifierCharacter { field } => write!(
                formatter,
                "resume field {field} contains an invalid identifier character"
            ),
        }
    }
}

impl std::error::Error for ResumeError {}
