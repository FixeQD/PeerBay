use std::fmt::{Display, Formatter};

use crate::messages::AppChannel;

use super::state::InvalidSessionTransition;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    InvalidTransition(InvalidSessionTransition),
    Closed,
    ChannelNotAttached,
    HandlerAlreadyRegistered {
        domain: AppChannel,
    },
    HandlerDomainMismatch {
        expected: AppChannel,
        got: AppChannel,
    },
    UnsupportedDomain {
        domain: AppChannel,
    },
}

impl Display for SessionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition(error) => write!(formatter, "{error}"),
            Self::Closed => write!(formatter, "session is closed"),
            Self::ChannelNotAttached => {
                write!(formatter, "session has no attached transport channel")
            }
            Self::HandlerAlreadyRegistered { domain } => {
                write!(
                    formatter,
                    "session handler already registered for {domain:?}"
                )
            }
            Self::HandlerDomainMismatch { expected, got } => {
                write!(
                    formatter,
                    "session handler domain mismatch: expected {expected:?}, got {got:?}"
                )
            }
            Self::UnsupportedDomain { domain } => {
                write!(formatter, "session handler domain unsupported: {domain:?}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

impl From<InvalidSessionTransition> for SessionError {
    fn from(error: InvalidSessionTransition) -> Self {
        Self::InvalidTransition(error)
    }
}
