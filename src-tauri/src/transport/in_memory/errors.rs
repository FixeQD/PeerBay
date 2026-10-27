use std::fmt::{Display, Formatter};

use super::super::{ChannelKind, TransportKind};

#[derive(Debug, PartialEq, Eq)]
pub enum InMemoryTransportError {
    DuplicatePeer,
    PeerNotFound,
    PeerEndpointMismatch,
    SelfConnection,
    ChannelNotFound,
    ChannelClosed,
    UnsupportedChannel {
        channel: ChannelKind,
    },
    QueueFull {
        limit: usize,
    },
    MessageTooLarge {
        length: usize,
        max: usize,
    },
    InvalidLimit {
        field: &'static str,
    },
    MessageLimitExceedsQueue {
        message_limit: usize,
        queue_limit: usize,
    },
    WrongTransportKind {
        expected: TransportKind,
        received: TransportKind,
    },
    NetworkPoisoned,
}

impl Display for InMemoryTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicatePeer => write!(formatter, "in-memory peer is already registered"),
            Self::PeerNotFound => write!(formatter, "in-memory peer is not registered"),
            Self::PeerEndpointMismatch => {
                write!(
                    formatter,
                    "in-memory peer endpoint does not match discovery"
                )
            }
            Self::SelfConnection => {
                write!(formatter, "in-memory transport cannot connect to itself")
            }
            Self::ChannelNotFound => write!(formatter, "in-memory channel is not registered"),
            Self::ChannelClosed => write!(formatter, "in-memory channel is closed"),
            Self::UnsupportedChannel { channel } => {
                write!(formatter, "in-memory channel is unsupported: {channel:?}")
            }
            Self::QueueFull { limit } => {
                write!(
                    formatter,
                    "in-memory channel queue is full at {limit} bytes"
                )
            }
            Self::MessageTooLarge { length, max } => write!(
                formatter,
                "in-memory message is too large: {length} bytes, limit is {max}"
            ),
            Self::InvalidLimit { field } => write!(formatter, "in-memory {field} must be positive"),
            Self::MessageLimitExceedsQueue {
                message_limit,
                queue_limit,
            } => write!(
                formatter,
                "in-memory message limit {message_limit} exceeds queue limit {queue_limit}"
            ),
            Self::WrongTransportKind { expected, received } => write!(
                formatter,
                "in-memory transport expects {expected:?}, received {received:?}"
            ),
            Self::NetworkPoisoned => write!(formatter, "in-memory network state is poisoned"),
        }
    }
}

impl std::error::Error for InMemoryTransportError {}
