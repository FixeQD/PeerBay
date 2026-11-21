//! Pairing message identifiers and payloads.

mod errors;
mod types;
mod validation;

pub use errors::PairingError;
pub use types::{
    PairingAccepted, PairingCancellationReason, PairingCancelled, PairingCode, PairingCommit,
    PairingConfirm, PairingNonce, PairingRejected, PairingRejectionReason, PairingReveal,
    PairingStart,
};

use proto::MessageType;

use super::AppMessageType;

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

impl From<PairingMessageType> for MessageType {
    fn from(value: PairingMessageType) -> Self {
        Self::from(AppMessageType::Pairing(value))
    }
}
