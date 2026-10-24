#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolErrorCode {
    InvalidEnvelope,
    UnsupportedVersion,
    UnknownMessageType,
    InvalidPayload,
    LimitExceeded,
    SequenceViolation,
    Unauthorized,
    Timeout,
    PeerUnavailable,
    Internal,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolErrorScope {
    Message,
    Channel,
    Session,
    Application,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProtocolError {
    pub code: ProtocolErrorCode,
    pub retryable: bool,
    pub scope: ProtocolErrorScope,
    pub correlation_id: String,
}

impl ProtocolError {
    pub fn new(
        code: ProtocolErrorCode,
        retryable: bool,
        scope: ProtocolErrorScope,
        correlation_id: impl Into<String>,
    ) -> Self {
        Self {
            code,
            retryable,
            scope,
            correlation_id: correlation_id.into(),
        }
    }
}
