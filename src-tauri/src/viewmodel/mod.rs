//! Projections of Rust application state for the WebView.

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
