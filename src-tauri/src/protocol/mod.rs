//! Versioned application-protocol boundary.

#![allow(dead_code)]

mod envelope;
mod errors;
mod json_framing;
mod limits;
mod message_types;

#[allow(unused_imports)]
pub(crate) use envelope::MessageEnvelope;
#[allow(unused_imports)]
pub(crate) use errors::{ProtocolError, ProtocolErrorCode, ProtocolErrorScope};
#[allow(unused_imports)]
pub(crate) use json_framing::{read_json_frame, write_json_frame};
#[allow(unused_imports)]
pub(crate) use limits::{
    DEFAULT_MAX_BATCH_ITEMS, DEFAULT_MAX_FRAME_SIZE, DEFAULT_MAX_JSON_SIZE,
    DEFAULT_MAX_PAYLOAD_SIZE, DEFAULT_MAX_STRING_LENGTH, ProtocolLimitError, ProtocolLimits,
};
#[allow(unused_imports)]
pub(crate) use message_types::{
    ClipboardMessageType, ControlMessageType, FileMessageType, InputMessageType, MediaMessageType,
    MessageChannel, MessageType, PairingMessageType,
};

pub(crate) const PROTOCOL_VERSION: u16 = 1;
