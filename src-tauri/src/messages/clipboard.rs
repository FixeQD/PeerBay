use super::AppMessageType;
use proto::MessageType;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClipboardMessageType {
    Offer,
    Request,
    Text,
    Policy,
    Ack,
}

message_type_strings!(ClipboardMessageType, {
    Offer => "clipboard.offer",
    Request => "clipboard.request",
    Text => "clipboard.text",
    Policy => "clipboard.policy",
    Ack => "clipboard.ack",
});

impl From<ClipboardMessageType> for MessageType {
    fn from(value: ClipboardMessageType) -> Self {
        Self::from(AppMessageType::Clipboard(value))
    }
}
