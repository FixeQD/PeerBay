use super::AppMessageType;
use proto::MessageType;

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

impl From<InputMessageType> for MessageType {
    fn from(value: InputMessageType) -> Self {
        Self::from(AppMessageType::Input(value))
    }
}
