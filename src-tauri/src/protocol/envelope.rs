#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use super::PROTOCOL_VERSION;
use super::limits::ProtocolLimits;
use super::message_types::MessageType;

/// Common envelope shared by every application-protocol message.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MessageEnvelope<T> {
    pub v: u16,
    pub id: String,
    #[serde(rename = "t")]
    pub message_type: MessageType,
    #[serde(rename = "sid")]
    pub session_id: String,
    pub seq: u64,
    #[serde(rename = "ts")]
    pub timestamp_ms: u64,
    pub body: T,
}

impl<T> MessageEnvelope<T> {
    pub fn new(
        id: impl Into<String>,
        message_type: MessageType,
        session_id: impl Into<String>,
        seq: u64,
        timestamp_ms: u64,
        body: T,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: id.into(),
            message_type,
            session_id: session_id.into(),
            seq,
            timestamp_ms,
            body,
        }
    }

    pub fn validate_limits(&self, limits: ProtocolLimits) -> eros::Result<()> {
        limits.validate_envelope(self)
    }
}
