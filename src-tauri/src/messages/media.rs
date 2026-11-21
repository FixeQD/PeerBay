use super::AppMessageType;
use proto::MessageType;

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

impl From<MediaMessageType> for MessageType {
    fn from(value: MediaMessageType) -> Self {
        Self::from(AppMessageType::Media(value))
    }
}
