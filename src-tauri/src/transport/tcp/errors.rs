use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub enum TcpTransportError {
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
}

impl Display for TcpTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongTransportKind { expected, received } => write!(
                formatter,
                "expected transport kind {expected:?}, received {received:?}"
            ),
            Self::BindFailed { address } => {
                write!(formatter, "failed to bind TCP listener to {address}")
            }
            Self::ConnectFailed { address } => {
                write!(formatter, "failed to connect TCP peer at {address}")
            }
            Self::Io { operation } => write!(formatter, "tcp io failure during {operation}"),
            Self::ChannelNotFound => write!(formatter, "tcp channel was not found"),
            Self::ChannelClosed => write!(formatter, "tcp channel is closed"),
            Self::MessageTooLarge { length, max } => {
                write!(
                    formatter,
                    "tcp message is too large: {length} bytes, limit is {max}"
                )
            }
            Self::UnsupportedChannel { channel } => {
                write!(
                    formatter,
                    "tcp transport does not support channel {channel:?}"
                )
            }
            Self::InvalidLocalAddress => write!(
                formatter,
                "local tcp address must be a valid socket address"
            ),
            Self::SelfConnection => write!(formatter, "tcp transport cannot connect to itself"),
        }
    }
}

impl std::error::Error for TcpTransportError {}
