use crate::viewmodel::snapshot::{MAX_DEVICES, MAX_SESSIONS, MAX_SNAPSHOT_BYTES, ViewModelError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewModelErrorCode {
    SnapshotEmittedAtStale,
    SnapshotDeviceLimit,
    SnapshotSessionLimit,
    SnapshotTooLarge,
    SnapshotSessionIntegrity,
    PeerFieldInvalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorFeatureScope {
    Snapshot,
    Devices,
    Sessions,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorDetail {
    Limit { value: usize, limit: usize },
    Field { field: String },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ErrorView {
    pub code: ViewModelErrorCode,
    pub user_message_key: String,
    pub retryable: bool,
    pub feature_scope: ErrorFeatureScope,
    pub detail: Option<ErrorDetail>,
}

impl From<&ViewModelError> for ErrorView {
    fn from(error: &ViewModelError) -> Self {
        match error {
            ViewModelError::EmittedAtTooOld { .. } => Self {
                code: ViewModelErrorCode::SnapshotEmittedAtStale,
                user_message_key: "error.snapshot_emitted_at_stale".to_owned(),
                retryable: false,
                feature_scope: ErrorFeatureScope::Snapshot,
                detail: None,
            },
            ViewModelError::TooManyDevices { count } => Self {
                code: ViewModelErrorCode::SnapshotDeviceLimit,
                user_message_key: "error.snapshot_device_limit".to_owned(),
                retryable: false,
                feature_scope: ErrorFeatureScope::Devices,
                detail: Some(ErrorDetail::Limit {
                    value: *count,
                    limit: MAX_DEVICES,
                }),
            },
            ViewModelError::TooManySessions { count } => Self {
                code: ViewModelErrorCode::SnapshotSessionLimit,
                user_message_key: "error.snapshot_session_limit".to_owned(),
                retryable: false,
                feature_scope: ErrorFeatureScope::Sessions,
                detail: Some(ErrorDetail::Limit {
                    value: *count,
                    limit: MAX_SESSIONS,
                }),
            },
            ViewModelError::SnapshotTooLarge { size } => Self {
                code: ViewModelErrorCode::SnapshotTooLarge,
                user_message_key: "error.snapshot_too_large".to_owned(),
                retryable: false,
                feature_scope: ErrorFeatureScope::Snapshot,
                detail: Some(ErrorDetail::Limit {
                    value: *size,
                    limit: MAX_SNAPSHOT_BYTES,
                }),
            },
            ViewModelError::UnknownSessionPeer => Self {
                code: ViewModelErrorCode::SnapshotSessionIntegrity,
                user_message_key: "error.snapshot_session_integrity".to_owned(),
                retryable: false,
                feature_scope: ErrorFeatureScope::Sessions,
                detail: None,
            },
            ViewModelError::InvalidPeerField { field } => Self {
                code: ViewModelErrorCode::PeerFieldInvalid,
                user_message_key: "error.peer_field_invalid".to_owned(),
                retryable: false,
                feature_scope: ErrorFeatureScope::Devices,
                detail: Some(ErrorDetail::Field {
                    field: field.to_string(),
                }),
            },
        }
    }
}
