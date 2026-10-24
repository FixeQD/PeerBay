#![allow(dead_code)]

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageChannel {
    Control,
    Pairing,
    Clipboard,
    Files,
    Input,
    Media,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlMessageType {
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
pub enum PairingMessageType {
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
pub enum ClipboardMessageType {
    Offer,
    Request,
    Text,
    Policy,
    Ack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileMessageType {
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
pub enum InputMessageType {
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
pub enum MediaMessageType {
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
pub enum MessageType {
    Control(ControlMessageType),
    Pairing(PairingMessageType),
    Clipboard(ClipboardMessageType),
    Files(FileMessageType),
    Input(InputMessageType),
    Media(MediaMessageType),
    Unknown(String),
}

impl MessageType {
    pub const fn channel(&self) -> MessageChannel {
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

    pub fn as_str(&self) -> &str {
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

    pub fn from_wire(value: String) -> Self {
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
            pub const fn as_str(self) -> &'static str {
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
