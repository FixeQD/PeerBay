//! Projections of Rust application state for the WebView.

pub mod command;
pub mod error;
pub mod snapshot;

pub use command::{
    AppCommand, AudioCommand, ClipboardCommand, CommandError, DevicesCommand, DiagnosticsCommand,
    FilesCommand, FolderShareCommand, IdentityCommand, InputCommand, PairCommand, PhoneCommand,
    PhoneScreenMode, PolicyCommand, ScreenCommand, SessionCommand, UiCommand,
};
pub use error::{ErrorDetail, ErrorFeatureScope, ErrorView, ViewModelErrorCode};
pub use snapshot::{
    AppStatusView, AppViewModel, DeviceAction, DeviceActionView, DeviceView,
    DiagnosticsSummaryView, FeatureRowState, FeatureRowView, LocalIdentityView, MAX_DEVICES,
    MAX_SESSIONS, MAX_SNAPSHOT_BYTES, SessionSummary, SessionView, SnapshotInputs, TrustStatus,
    VIEWMODEL_SCHEMA_VERSION, ViewModelError,
};

use crate::redaction::RedactionPolicy;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub struct ViewModelGateway {
    schema_version: u16,
    redaction: RedactionPolicy,
}

impl ViewModelGateway {
    pub const fn new() -> Self {
        Self {
            schema_version: 1,
            redaction: RedactionPolicy::privacy_safe(),
        }
    }

    pub fn is_privacy_safe(self) -> bool {
        self.schema_version == 1 && self.redaction.is_privacy_safe()
    }
}

impl Default for ViewModelGateway {
    fn default() -> Self {
        Self::new()
    }
}
