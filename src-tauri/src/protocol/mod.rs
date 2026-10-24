//! Versioned application-protocol boundary.

#![allow(dead_code)]

pub mod capabilities;
pub mod envelope;
pub mod errors;
pub mod json_framing;
pub mod limits;
pub mod message_types;
pub mod pairing;
pub mod policy;
pub mod resume;
pub mod sequence;

pub use capabilities::{CapabilityDocument, CapabilityError, NegotiatedCapabilities};
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
pub use pairing::{
    PairingAccepted, PairingCancellationReason, PairingCancelled, PairingCode, PairingCommit,
    PairingConfirm, PairingError, PairingNonce, PairingRejected, PairingRejectionReason,
    PairingReveal, PairingStart,
};
pub use policy::{
    FeaturePolicy, PolicyError, PolicyGetRequest, PolicyGetResponse, PolicyRejection,
    PolicyRejectionReason, PolicySetRequest, PolicySetResponse, UserPolicyState,
};
pub use resume::{
    ChannelMigration, ChannelResumeCursor, ResumeError, ResumeKey, ResumeRejectionReason,
    SessionChannel, SessionResumeAccepted, SessionResumeRejected, SessionResumeRequest,
};
pub use sequence::{SequenceError, SequenceTracker};

pub const PROTOCOL_VERSION: u16 = 1;
