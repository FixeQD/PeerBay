use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub enum TlsTransportError {
    WrongTransportKind {
        expected: super::super::TransportKind,
        received: super::super::TransportKind,
    },
    BindFailed {
        address: String,
    },
    ConnectFailed {
        address: String,
    },
    Io {
        operation: &'static str,
    },
    ChannelNotFound,
    ChannelClosed,
    MessageTooLarge {
        length: usize,
        max: usize,
    },
    UnsupportedChannel {
        channel: super::super::ChannelKind,
    },
    InvalidLocalAddress,
    SelfConnection,
    Tls {
        detail: String,
    },
}

impl Display for TlsTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongTransportKind { expected, received } => {
                write!(formatter, "expected {expected:?}, received {received:?}")
            }
            Self::BindFailed { address } => {
                write!(formatter, "failed to bind TLS listener to {address}")
            }
            Self::ConnectFailed { address } => {
                write!(formatter, "failed to connect TLS peer at {address}")
            }
            Self::Io { operation } => write!(formatter, "tls io failure during {operation}"),
            Self::ChannelNotFound => write!(formatter, "tls channel was not found"),
            Self::ChannelClosed => write!(formatter, "tls channel is closed"),
            Self::MessageTooLarge { length, max } => {
                write!(
                    formatter,
                    "tls message is too large: {length} bytes, limit is {max}"
                )
            }
            Self::UnsupportedChannel { channel } => {
                write!(formatter, "unsupported channel {channel:?}")
            }
            Self::InvalidLocalAddress => write!(formatter, "invalid local address"),
            Self::SelfConnection => write!(formatter, "cannot connect to self"),
            Self::Tls { detail } => write!(formatter, "tls failure: {detail}"),
        }
    }
}

impl std::error::Error for TlsTransportError {}
