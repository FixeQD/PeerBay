#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProtocolErrorCode {
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
pub(crate) enum ProtocolErrorScope {
    Message,
    Channel,
    Session,
    Application,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(crate) struct ProtocolError {
    pub(crate) code: ProtocolErrorCode,
    pub(crate) retryable: bool,
    pub(crate) scope: ProtocolErrorScope,
    pub(crate) correlation_id: String,
}

impl ProtocolError {
    pub(crate) fn new(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_payload_serializes_stable_wire_fields() {
        let error = ProtocolError::new(
            ProtocolErrorCode::InvalidPayload,
            false,
            ProtocolErrorScope::Message,
            "corr-123",
        );

        let value = serde_json::to_value(&error).expect("protocol error should serialize");

        assert_eq!(value["code"], "invalid_payload");
        assert_eq!(value["retryable"], false);
        assert_eq!(value["scope"], "message");
        assert_eq!(value["correlation_id"], "corr-123");
    }

    #[test]
    fn error_payload_roundtrips_all_structured_fields() {
        let original = ProtocolError::new(
            ProtocolErrorCode::PeerUnavailable,
            true,
            ProtocolErrorScope::Session,
            "session-connect-7",
        );

        let encoded = serde_json::to_string(&original).expect("protocol error should serialize");
        let decoded: ProtocolError =
            serde_json::from_str(&encoded).expect("protocol error should deserialize");

        assert_eq!(decoded, original);
    }

    #[test]
    fn error_codes_and_scopes_cover_the_wire_contract() {
        let codes = [
            ProtocolErrorCode::InvalidEnvelope,
            ProtocolErrorCode::UnsupportedVersion,
            ProtocolErrorCode::UnknownMessageType,
            ProtocolErrorCode::InvalidPayload,
            ProtocolErrorCode::LimitExceeded,
            ProtocolErrorCode::SequenceViolation,
            ProtocolErrorCode::Unauthorized,
            ProtocolErrorCode::Timeout,
            ProtocolErrorCode::PeerUnavailable,
            ProtocolErrorCode::Internal,
        ];
        let scopes = [
            ProtocolErrorScope::Message,
            ProtocolErrorScope::Channel,
            ProtocolErrorScope::Session,
            ProtocolErrorScope::Application,
        ];

        assert_eq!(codes.len(), 10);
        assert_eq!(scopes.len(), 4);
    }
}
