#![allow(dead_code)]

use std::collections::HashMap;
use std::fmt::{Display, Formatter};

use super::envelope::MessageEnvelope;
use super::limits::ProtocolLimits;
use super::message_types::MessageChannel;

/// Per-session guard for monotonic message sequence numbers.
#[derive(Debug)]
pub struct SequenceTracker {
    session_id: String,
    last_accepted: HashMap<MessageChannel, u64>,
}

impl SequenceTracker {
    /// Creates a tracker bound to one authenticated session identifier.
    pub fn new(session_id: impl Into<String>) -> eros::Result<Self> {
        let session_id = session_id.into();
        ProtocolLimits::default().validate_string("sid", &session_id)?;

        Ok(Self {
            session_id,
            last_accepted: HashMap::new(),
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the greatest accepted sequence number for a channel.
    pub fn last_accepted(&self, channel: MessageChannel) -> Option<u64> {
        self.last_accepted.get(&channel).copied()
    }

    /// Accepts a message if it belongs to this session and advances its channel sequence
    pub fn accept<T>(&mut self, envelope: &MessageEnvelope<T>) -> eros::Result<()> {
        if envelope.session_id != self.session_id {
            return Err(eros::error!(SequenceError::SessionMismatch {
                expected: self.session_id.clone(),
                received: envelope.session_id.clone(),
            }));
        }

        let channel = envelope.message_type.channel();
        if let Some(last_accepted) = self.last_accepted(channel) {
            if envelope.seq == last_accepted {
                return Err(eros::error!(SequenceError::Duplicate {
                    channel,
                    seq: envelope.seq,
                }));
            }

            if envelope.seq < last_accepted {
                return Err(eros::error!(SequenceError::Replay {
                    channel,
                    seq: envelope.seq,
                    last_accepted,
                }));
            }
        }

        self.last_accepted.insert(channel, envelope.seq);
        Ok(())
    }

    /// Restores the accepted-sequence watermark for a channel after a resume
    pub fn restore(&mut self, channel: MessageChannel, last_accepted: u64) -> eros::Result<()> {
        let current = self.last_accepted(channel);
        if let Some(current) = current.filter(|current| last_accepted < *current) {
            return Err(eros::error!(SequenceError::RestoreRegression {
                channel,
                requested: last_accepted,
                current,
            }));
        }

        self.last_accepted.insert(channel, last_accepted);
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SequenceError {
    SessionMismatch {
        expected: String,
        received: String,
    },
    Duplicate {
        channel: MessageChannel,
        seq: u64,
    },
    Replay {
        channel: MessageChannel,
        seq: u64,
        last_accepted: u64,
    },
    RestoreRegression {
        channel: MessageChannel,
        requested: u64,
        current: u64,
    },
}

impl Display for SequenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionMismatch { expected, received } => write!(
                formatter,
                "protocol session mismatch: expected {expected}, received {received}"
            ),
            Self::Duplicate { channel, seq } => {
                write!(
                    formatter,
                    "duplicate protocol sequence {seq} on {channel:?}"
                )
            }
            Self::Replay {
                channel,
                seq,
                last_accepted,
            } => write!(
                formatter,
                "replayed protocol sequence {seq} on {channel:?}; last accepted is {last_accepted}"
            ),
            Self::RestoreRegression {
                channel,
                requested,
                current,
            } => write!(
                formatter,
                "restored sequence watermark {requested} for {channel:?} would regress below the accepted {current}"
            ),
        }
    }
}

impl std::error::Error for SequenceError {}
