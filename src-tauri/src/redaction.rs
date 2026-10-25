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

    pub fn redact_log_entry(entry: &str, privacy_mode: bool) -> String {
        let mut result = entry.to_string();
        if privacy_mode {
            result = Self::redact_path(&result);
            result = Self::redact_payload(&result, 40);
        }
        result
    }

    pub fn redact_string(value: &str, redaction_keyword: Option<&str>) -> String {
        if value.is_empty() {
            return "***".to_string();
        }
        if let Some(keyword) = redaction_keyword {
            if value.contains(keyword) {
                return Self::redact_token_or_fingerprint(value);
            }
        }
        // Default safe: show first 4 chars only for any secret-like string
        if value.len() > 8 {
            format!("{}***", &value[..4])
        } else {
            "***".to_string()
        }
    }

    pub fn redact_pairing_token_hash(hash: &str) -> String {
        Self::redact_token_or_fingerprint(hash)
    }

    pub fn redact_clipboard_preview(text: &str) -> String {
        Self::redact_payload(text, 10)
    }

    pub fn redact_notification(text: &str) -> String {
        Self::redact_payload(text, 20)
    }

    pub fn redact_input_payload(text: &str) -> String {
        Self::redact_payload(text, 0) // Never expose full input payload in log/DTO
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
