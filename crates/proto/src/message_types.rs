use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageType {
    Control(ControlMessageType),
    Unknown(String),
}

impl MessageType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Control(message) => message.as_str(),
            Self::Unknown(wire_name) => wire_name,
        }
    }

    /// Resolves protocol-level control identifiers
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
