//! Boundary for removing secrets and private data before view-model emission.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedactionPolicy {
    allow_private_paths: bool,
    allow_private_payloads: bool,
}

impl RedactionPolicy {
    pub fn redact_token_or_fingerprint(value: &str) -> String {
        if value.len() <= 4 {
            return "***".to_string();
        }
        format!("{}***", &value[..4])
    }

    pub fn redact_path(path: &str) -> String {
        std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| format!("<redacted_path>:{}>", n))
            .unwrap_or_else(|| "<redacted_path>".to_string())
    }

    pub fn redact_payload(text: &str, max_preview: usize) -> String {
        if text.len() <= max_preview {
            return text.to_string();
        }
        format!(
            "{}...[redacted {} bytes]",
            &text[..max_preview],
            text.len() - max_preview
        )
    }

    pub const fn privacy_safe() -> Self {
        Self {
            allow_private_paths: false,
            allow_private_payloads: false,
        }
    }

    pub const fn is_privacy_safe(self) -> bool {
        !self.allow_private_paths && !self.allow_private_payloads
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::privacy_safe()
    }
}
