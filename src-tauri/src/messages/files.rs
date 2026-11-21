use proto::MessageType;

use super::AppMessageType;

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

impl From<FileMessageType> for MessageType {
    fn from(value: FileMessageType) -> Self {
        Self::from(AppMessageType::Files(value))
    }
}
