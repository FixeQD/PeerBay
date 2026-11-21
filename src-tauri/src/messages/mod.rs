#[macro_use]
mod macros;

mod clipboard;
mod files;
mod input;
mod media;
pub mod pairing;
mod phone;
pub mod policy;
pub mod privilege;

pub use clipboard::ClipboardMessageType;
pub use files::FileMessageType;
pub use input::InputMessageType;
pub use media::MediaMessageType;
pub use pairing::{
    PairingAccepted, PairingCancellationReason, PairingCancelled, PairingCode, PairingCommit,
    PairingConfirm, PairingError, PairingMessageType, PairingNonce, PairingRejected,
    PairingRejectionReason, PairingReveal, PairingStart,
};
pub use phone::PhoneMessageType;
pub use policy::{
    FeaturePolicy, PolicyError, PolicyGetRequest, PolicyGetResponse, PolicyRejection,
    PolicyRejectionReason, PolicySetRequest, PolicySetResponse, UserPolicyState,
};
pub use privilege::{
    PrivilegeAdbTransport, PrivilegeAuthority, PrivilegeBackendSnapshot, PrivilegeCancelRequest,
    PrivilegeCancellationReason, PrivilegeCapabilities, PrivilegeDecision, PrivilegeError,
    PrivilegeProof, PrivilegeProvider, PrivilegeRequest, PrivilegeState, PrivilegeStateMessage,
};

use proto::MessageType;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum AppChannel {
    Control,
    Pairing,
    Clipboard,
    Files,
    Input,
    Media,
    Phone,
    Unknown,
}

impl AsRef<str> for AppChannel {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<AppChannel> for String {
    fn from(value: AppChannel) -> Self {
        value.as_str().to_owned()
    }
}

impl AppChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Pairing => "pairing",
            Self::Clipboard => "clipboard",
            Self::Files => "files",
            Self::Input => "input",
            Self::Media => "media",
            Self::Phone => "phone",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppMessageType {
    Pairing(PairingMessageType),
    Clipboard(ClipboardMessageType),
    Files(FileMessageType),
    Input(InputMessageType),
    Media(MediaMessageType),
    Phone(PhoneMessageType),
}

impl AppMessageType {
    pub fn from_wire(value: &str) -> Option<Self> {
        if let Some(message) = PairingMessageType::from_wire(value) {
            return Some(Self::Pairing(message));
        }
        if let Some(message) = ClipboardMessageType::from_wire(value) {
            return Some(Self::Clipboard(message));
        }
        if let Some(message) = FileMessageType::from_wire(value) {
            return Some(Self::Files(message));
        }
        if let Some(message) = InputMessageType::from_wire(value) {
            return Some(Self::Input(message));
        }
        if let Some(message) = MediaMessageType::from_wire(value) {
            return Some(Self::Media(message));
        }
        if let Some(message) = PhoneMessageType::from_wire(value) {
            return Some(Self::Phone(message));
        }
        None
    }

    pub const fn channel(self) -> AppChannel {
        match self {
            Self::Pairing(_) => AppChannel::Pairing,
            Self::Clipboard(_) => AppChannel::Clipboard,
            Self::Files(_) => AppChannel::Files,
            Self::Input(_) => AppChannel::Input,
            Self::Media(_) => AppChannel::Media,
            Self::Phone(_) => AppChannel::Phone,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pairing(message) => message.as_str(),
            Self::Clipboard(message) => message.as_str(),
            Self::Files(message) => message.as_str(),
            Self::Input(message) => message.as_str(),
            Self::Media(message) => message.as_str(),
            Self::Phone(message) => message.as_str(),
        }
    }
}

impl From<AppMessageType> for MessageType {
    fn from(value: AppMessageType) -> Self {
        Self::Unknown(value.as_str().to_owned())
    }
}
