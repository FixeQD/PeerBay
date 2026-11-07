use std::fmt::{Display, Formatter};

use super::state::InvalidSessionTransition;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    InvalidTransition(InvalidSessionTransition),
    Closed,
}

impl Display for SessionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition(error) => write!(formatter, "{error}"),
            Self::Closed => write!(formatter, "session is closed"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<InvalidSessionTransition> for SessionError {
    fn from(error: InvalidSessionTransition) -> Self {
        Self::InvalidTransition(error)
    }
}
