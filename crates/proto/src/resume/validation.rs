use std::collections::HashSet;

use crate::limits::ProtocolLimits;

use super::errors::ResumeError;
use super::types::ChannelResumeCursor;

pub(super) fn validate_resume_window(requested_at_ms: u64, expires_at_ms: u64) -> eros::Result<()> {
    if requested_at_ms == 0 {
        return Err(eros::error!(ResumeError::ZeroTimestamp {
            field: "requested_at_ms",
        }));
    }
    if expires_at_ms <= requested_at_ms {
        return Err(eros::error!(ResumeError::ExpiryNotAfterRequest {
            requested_at_ms,
            expires_at_ms,
        }));
    }

    Ok(())
}

pub(super) fn validate_cursors(cursors: &[ChannelResumeCursor]) -> eros::Result<()> {
    if cursors.is_empty() {
        return Err(eros::error!(ResumeError::EmptyCursors));
    }
    ProtocolLimits::default().validate_batch("cursors", cursors.len())?;

    let mut channels = HashSet::with_capacity(cursors.len());
    for cursor in cursors {
        if !channels.insert(cursor.channel) {
            return Err(eros::error!(ResumeError::DuplicateChannel {
                channel: cursor.channel,
            }));
        }
    }

    Ok(())
}

pub(super) fn validate_identifier(field: &'static str, value: &str) -> eros::Result<()> {
    let limits = ProtocolLimits::default();
    limits.validate_string(field, value)?;

    if value != value.trim() {
        return Err(eros::error!(ResumeError::UnexpectedWhitespace { field }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(ResumeError::ControlCharacter { field }));
    }
    if value.chars().any(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-' | ':')
    }) {
        return Err(eros::error!(ResumeError::InvalidIdentifierCharacter {
            field
        }));
    }

    Ok(())
}
