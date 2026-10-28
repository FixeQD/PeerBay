use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    BindFailed,
    Io,
    InvalidAddress,
    InvalidJson,
    InvalidSize { length: usize, max: usize },
    InvalidBeacon,
    ReceiveTimeout,
    TooManyPeers,
}

impl Display for DiscoveryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindFailed => write!(formatter, "failed to bind discovery socket"),
            Self::Io => write!(formatter, "discovery io failure"),
            Self::InvalidAddress => write!(formatter, "invalid discovery address"),
            Self::InvalidJson => write!(formatter, "invalid discovery json"),
            Self::InvalidSize { length, max } => {
                write!(formatter, "discovery message is too large: {length}, limit {max}")
            }
            Self::InvalidBeacon => write!(formatter, "invalid discovery beacon"),
            Self::ReceiveTimeout => write!(formatter, "discovery receive timed out"),
            Self::TooManyPeers => write!(formatter, "discovery peer table is full"),
        }
    }
}

impl std::error::Error for DiscoveryError {}
