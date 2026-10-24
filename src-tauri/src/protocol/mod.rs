//! Versioned application-protocol boundary.

#![allow(dead_code)]

pub mod envelope;
pub mod errors;
pub mod json_framing;
pub mod limits;
pub mod message_types;
pub mod sequence;

pub use envelope::MessageEnvelope;
pub use errors::{ProtocolError, ProtocolErrorCode, ProtocolErrorScope};
pub use json_framing::{read_json_frame, write_json_frame};
pub use limits::{
    DEFAULT_MAX_BATCH_ITEMS, DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_JSON_SIZE,
    DEFAULT_MAX_PAYLOAD_SIZE, DEFAULT_MAX_STRING_LENGTH, ProtocolLimitError, ProtocolLimits,
};
pub use message_types::{
    ClipboardMessageType, ControlMessageType, FileMessageType, InputMessageType, MediaMessageType,
    MessageChannel, MessageType, PairingMessageType,
};
pub use sequence::{SequenceError, SequenceTracker};

pub const PROTOCOL_VERSION: u16 = 1;
