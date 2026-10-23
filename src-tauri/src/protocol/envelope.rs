#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use super::PROTOCOL_VERSION;
use super::limits::ProtocolLimits;
use super::message_types::MessageType;

/// Common envelope shared by every application-protocol message.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct MessageEnvelope<T> {
    pub(crate) v: u16,
    pub(crate) id: String,
    #[serde(rename = "t")]
    pub(crate) message_type: MessageType,
    #[serde(rename = "sid")]
    pub(crate) session_id: String,
    pub(crate) seq: u64,
    #[serde(rename = "ts")]
    pub(crate) timestamp_ms: u64,
    pub(crate) body: T,
}

impl<T> MessageEnvelope<T> {
    pub(crate) fn new(
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

    pub(crate) fn validate_limits(&self, limits: ProtocolLimits) -> eros::Result<()> {
        limits.validate_envelope(self)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::protocol::{ClipboardMessageType, ControlMessageType, MessageType};

    #[test]
    fn envelope_serializes_the_versioned_wire_fields() {
        let envelope = MessageEnvelope::new(
            "message-uuid",
            MessageType::Clipboard(ClipboardMessageType::Text),
            "session-id",
            42,
            1_792_700_000_000,
            json!({ "text": "hello" }),
        );

        let value = serde_json::to_value(&envelope).expect("envelope should serialize");

        assert_eq!(value["v"], PROTOCOL_VERSION);
        assert_eq!(value["id"], "message-uuid");
        assert_eq!(value["t"], "clipboard.text");
        assert_eq!(value["sid"], "session-id");
        assert_eq!(value["seq"], 42);
        assert_eq!(value["ts"], 1_792_700_000_000u64);
        assert_eq!(value["body"]["text"], "hello");
    }

    #[test]
    fn envelope_roundtrips_without_changing_the_body() {
        let original = MessageEnvelope::new(
            "message-uuid",
            MessageType::Control(ControlMessageType::Ping),
            "session-id",
            7,
            1_792_700_000_001,
            json!({ "nonce": 3, "ack": true }),
        );

        let encoded = serde_json::to_string(&original).expect("envelope should serialize");
        let decoded: MessageEnvelope<serde_json::Value> =
            serde_json::from_str(&encoded).expect("envelope should deserialize");

        assert_eq!(decoded, original);
    }
}
