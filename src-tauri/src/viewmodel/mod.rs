//! Projections of Rust application state for the WebView.

use crate::redaction::RedactionPolicy;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ViewModelGateway {
    schema_version: u16,
    redaction: RedactionPolicy,
}

impl ViewModelGateway {
    pub(crate) const fn new() -> Self {
        Self {
            schema_version: 1,
            redaction: RedactionPolicy::privacy_safe(),
        }
    }

    #[cfg(test)]
    fn is_privacy_safe(self) -> bool {
        self.schema_version == 1 && self.redaction.is_privacy_safe()
    }
}

impl Default for ViewModelGateway {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ViewModelGateway;

    #[test]
    fn gateway_starts_with_privacy_safe_defaults() {
        assert!(ViewModelGateway::new().is_privacy_safe());
    }
}
