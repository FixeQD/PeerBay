//! Versioned application-protocol boundary.

#![allow(dead_code)]

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(crate) const PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MessageChannel {
    Control,
    Pairing,
    Clipboard,
    Files,
    Input,
    Media,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlMessageType {
    Hello,
    Welcome,
    Error,
    Ping,
    Pong,
    Bye,
    SessionTakeover,
    SessionRelease,
    SessionResume,
    CapabilitiesRequest,
    CapabilitiesResponse,
    PolicyGet,
    PolicySet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PairingMessageType {
    Start,
    Commit,
    Nonce,
    Reveal,
    Code,
    Confirm,
    Accepted,
    Rejected,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClipboardMessageType {
    Offer,
    Request,
    Text,
    Policy,
    Ack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileMessageType {
    Offer,
    Accept,
    Refuse,
    Chunk,
    End,
    Done,
    Cancel,
    Resume,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputMessageType {
    Layout,
    Take,
    Accept,
    Release,
    Move,
    ButtonDown,
    ButtonUp,
    Wheel,
    KeyDown,
    KeyUp,
    Gesture,
    Home,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MediaMessageType {
    ScreenOffer,
    ScreenAnswer,
    ScreenIce,
    ScreenPolicy,
    ScreenStart,
    ScreenStop,
    ScreenState,
    AudioOffer,
    AudioAnswer,
    AudioIce,
    AudioStop,
    AudioState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MessageType {
    Control(ControlMessageType),
    Pairing(PairingMessageType),
    Clipboard(ClipboardMessageType),
    Files(FileMessageType),
    Input(InputMessageType),
    Media(MediaMessageType),
    Unknown(String),
}

impl MessageType {
    pub(crate) const fn channel(&self) -> MessageChannel {
        match self {
            Self::Control(_) => MessageChannel::Control,
            Self::Pairing(_) => MessageChannel::Pairing,
            Self::Clipboard(_) => MessageChannel::Clipboard,
            Self::Files(_) => MessageChannel::Files,
            Self::Input(_) => MessageChannel::Input,
            Self::Media(_) => MessageChannel::Media,
            Self::Unknown(_) => MessageChannel::Unknown,
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Control(message) => message.as_str(),
            Self::Pairing(message) => message.as_str(),
            Self::Clipboard(message) => message.as_str(),
            Self::Files(message) => message.as_str(),
            Self::Input(message) => message.as_str(),
            Self::Media(message) => message.as_str(),
            Self::Unknown(message) => message,
        }
    }

    pub(crate) fn from_wire(value: String) -> Self {
        match value.as_str() {
            "hello" => Self::Control(ControlMessageType::Hello),
            "welcome" => Self::Control(ControlMessageType::Welcome),
            "error" => Self::Control(ControlMessageType::Error),
            "ping" => Self::Control(ControlMessageType::Ping),
            "pong" => Self::Control(ControlMessageType::Pong),
            "bye" => Self::Control(ControlMessageType::Bye),
            "session.takeover" => Self::Control(ControlMessageType::SessionTakeover),
            "session.release" => Self::Control(ControlMessageType::SessionRelease),
            "session.resume" => Self::Control(ControlMessageType::SessionResume),
            "capabilities.request" => Self::Control(ControlMessageType::CapabilitiesRequest),
            "capabilities.response" => Self::Control(ControlMessageType::CapabilitiesResponse),
            "policy.get" => Self::Control(ControlMessageType::PolicyGet),
            "policy.set" => Self::Control(ControlMessageType::PolicySet),
            "pair.start" => Self::Pairing(PairingMessageType::Start),
            "pair.commit" => Self::Pairing(PairingMessageType::Commit),
            "pair.nonce" => Self::Pairing(PairingMessageType::Nonce),
            "pair.reveal" => Self::Pairing(PairingMessageType::Reveal),
            "pair.code" => Self::Pairing(PairingMessageType::Code),
            "pair.confirm" => Self::Pairing(PairingMessageType::Confirm),
            "pair.accepted" => Self::Pairing(PairingMessageType::Accepted),
            "pair.rejected" => Self::Pairing(PairingMessageType::Rejected),
            "pair.cancelled" => Self::Pairing(PairingMessageType::Cancelled),
            "clipboard.offer" => Self::Clipboard(ClipboardMessageType::Offer),
            "clipboard.request" => Self::Clipboard(ClipboardMessageType::Request),
            "clipboard.text" => Self::Clipboard(ClipboardMessageType::Text),
            "clipboard.policy" => Self::Clipboard(ClipboardMessageType::Policy),
            "clipboard.ack" => Self::Clipboard(ClipboardMessageType::Ack),
            "file.offer" => Self::Files(FileMessageType::Offer),
            "file.accept" => Self::Files(FileMessageType::Accept),
            "file.refuse" => Self::Files(FileMessageType::Refuse),
            "file.chunk" => Self::Files(FileMessageType::Chunk),
            "file.end" => Self::Files(FileMessageType::End),
            "file.done" => Self::Files(FileMessageType::Done),
            "file.cancel" => Self::Files(FileMessageType::Cancel),
            "file.resume" => Self::Files(FileMessageType::Resume),
            "file.error" => Self::Files(FileMessageType::Error),
            "input.layout" => Self::Input(InputMessageType::Layout),
            "input.take" => Self::Input(InputMessageType::Take),
            "input.accept" => Self::Input(InputMessageType::Accept),
            "input.release" => Self::Input(InputMessageType::Release),
            "input.move" => Self::Input(InputMessageType::Move),
            "input.button_down" => Self::Input(InputMessageType::ButtonDown),
            "input.button_up" => Self::Input(InputMessageType::ButtonUp),
            "input.wheel" => Self::Input(InputMessageType::Wheel),
            "input.key_down" => Self::Input(InputMessageType::KeyDown),
            "input.key_up" => Self::Input(InputMessageType::KeyUp),
            "input.gesture" => Self::Input(InputMessageType::Gesture),
            "input.home" => Self::Input(InputMessageType::Home),
            "screen.offer" => Self::Media(MediaMessageType::ScreenOffer),
            "screen.answer" => Self::Media(MediaMessageType::ScreenAnswer),
            "screen.ice" => Self::Media(MediaMessageType::ScreenIce),
            "screen.policy" => Self::Media(MediaMessageType::ScreenPolicy),
            "screen.start" => Self::Media(MediaMessageType::ScreenStart),
            "screen.stop" => Self::Media(MediaMessageType::ScreenStop),
            "screen.state" => Self::Media(MediaMessageType::ScreenState),
            "audio.offer" => Self::Media(MediaMessageType::AudioOffer),
            "audio.answer" => Self::Media(MediaMessageType::AudioAnswer),
            "audio.ice" => Self::Media(MediaMessageType::AudioIce),
            "audio.stop" => Self::Media(MediaMessageType::AudioStop),
            "audio.state" => Self::Media(MediaMessageType::AudioState),
            _ => Self::Unknown(value),
        }
    }
}

impl Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() {
            return Err(D::Error::custom("message type cannot be empty"));
        }
        Ok(Self::from_wire(value))
    }
}

macro_rules! message_type_strings {
    ($type:ty, { $( $variant:ident => $wire:literal ),+ $(,)? }) => {
        impl $type {
            pub(crate) const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )+
                }
            }
        }
    };
}

message_type_strings!(ControlMessageType, {
    Hello => "hello",
    Welcome => "welcome",
    Error => "error",
    Ping => "ping",
    Pong => "pong",
    Bye => "bye",
    SessionTakeover => "session.takeover",
    SessionRelease => "session.release",
    SessionResume => "session.resume",
    CapabilitiesRequest => "capabilities.request",
    CapabilitiesResponse => "capabilities.response",
    PolicyGet => "policy.get",
    PolicySet => "policy.set",
});

message_type_strings!(PairingMessageType, {
    Start => "pair.start",
    Commit => "pair.commit",
    Nonce => "pair.nonce",
    Reveal => "pair.reveal",
    Code => "pair.code",
    Confirm => "pair.confirm",
    Accepted => "pair.accepted",
    Rejected => "pair.rejected",
    Cancelled => "pair.cancelled",
});

message_type_strings!(ClipboardMessageType, {
    Offer => "clipboard.offer",
    Request => "clipboard.request",
    Text => "clipboard.text",
    Policy => "clipboard.policy",
    Ack => "clipboard.ack",
});

message_type_strings!(FileMessageType, {
    Offer => "file.offer",
    Accept => "file.accept",
    Refuse => "file.refuse",
    Chunk => "file.chunk",
    End => "file.end",
    Done => "file.done",
    Cancel => "file.cancel",
    Resume => "file.resume",
    Error => "file.error",
});

message_type_strings!(InputMessageType, {
    Layout => "input.layout",
    Take => "input.take",
    Accept => "input.accept",
    Release => "input.release",
    Move => "input.move",
    ButtonDown => "input.button_down",
    ButtonUp => "input.button_up",
    Wheel => "input.wheel",
    KeyDown => "input.key_down",
    KeyUp => "input.key_up",
    Gesture => "input.gesture",
    Home => "input.home",
});

message_type_strings!(MediaMessageType, {
    ScreenOffer => "screen.offer",
    ScreenAnswer => "screen.answer",
    ScreenIce => "screen.ice",
    ScreenPolicy => "screen.policy",
    ScreenStart => "screen.start",
    ScreenStop => "screen.stop",
    ScreenState => "screen.state",
    AudioOffer => "audio.offer",
    AudioAnswer => "audio.answer",
    AudioIce => "audio.ice",
    AudioStop => "audio.stop",
    AudioState => "audio.state",
});

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
            message_type: message_type.into(),
            session_id: session_id.into(),
            seq,
            timestamp_ms,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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

    #[test]
    fn known_identifiers_keep_their_channel_and_wire_name() {
        let identifiers = [
            (
                MessageType::Control(ControlMessageType::Hello),
                MessageChannel::Control,
                "hello",
            ),
            (
                MessageType::Pairing(PairingMessageType::Confirm),
                MessageChannel::Pairing,
                "pair.confirm",
            ),
            (
                MessageType::Clipboard(ClipboardMessageType::Offer),
                MessageChannel::Clipboard,
                "clipboard.offer",
            ),
            (
                MessageType::Files(FileMessageType::Chunk),
                MessageChannel::Files,
                "file.chunk",
            ),
            (
                MessageType::Input(InputMessageType::KeyDown),
                MessageChannel::Input,
                "input.key_down",
            ),
            (
                MessageType::Media(MediaMessageType::ScreenState),
                MessageChannel::Media,
                "screen.state",
            ),
        ];

        for (identifier, channel, wire_name) in identifiers {
            assert_eq!(identifier.channel(), channel);
            assert_eq!(identifier.as_str(), wire_name);
            assert_eq!(
                serde_json::to_string(&identifier).expect("identifier should serialize"),
                format!("\"{wire_name}\"")
            );
        }
    }

    #[test]
    fn identifiers_parse_known_and_preserve_unknown_wire_names() {
        let known: MessageType =
            serde_json::from_str("\"session.resume\"").expect("known identifier should parse");
        assert_eq!(
            known,
            MessageType::Control(ControlMessageType::SessionResume)
        );

        let unknown: MessageType =
            serde_json::from_str("\"future.message\"").expect("unknown identifier should parse");
        assert_eq!(unknown, MessageType::Unknown("future.message".to_owned()));
        assert_eq!(unknown.channel(), MessageChannel::Unknown);
        assert_eq!(unknown.as_str(), "future.message");
    }

    #[test]
    fn empty_identifier_is_rejected_during_deserialization() {
        let result = serde_json::from_str::<MessageType>("\"\"");

        assert!(result.is_err());
    }
}
