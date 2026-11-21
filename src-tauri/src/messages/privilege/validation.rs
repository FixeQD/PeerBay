use std::collections::HashSet;

use super::errors::PrivilegeError;
use proto::ProtocolLimits;

pub(super) fn validate_safe_identifier(field: &'static str, value: &str) -> eros::Result<()> {
    ProtocolLimits::default().validate_string(field, value)?;

    if value != value.trim() {
        return Err(eros::error!(PrivilegeError::UnexpectedWhitespace { field }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(PrivilegeError::ControlCharacter { field }));
    }
    if value.chars().any(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-' | ':')
    }) {
        return Err(eros::error!(PrivilegeError::InvalidIdentifierCharacter {
            field
        }));
    }

    Ok(())
}

pub(super) fn validate_optional_safe_identifier(
    field: &'static str,
    value: Option<&str>,
) -> eros::Result<()> {
    if let Some(value) = value {
        validate_safe_identifier(field, value)?;
    }

    Ok(())
}

pub(super) fn validate_identifier_list(field: &'static str, values: &[String]) -> eros::Result<()> {
    ProtocolLimits::default().validate_batch(field, values.len())?;

    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        validate_safe_identifier(field, value)?;
        if !seen.insert(value.as_str()) {
            return Err(eros::error!(PrivilegeError::DuplicateValue {
                field,
                value: value.clone(),
            }));
        }
    }

    Ok(())
}

pub(super) fn validate_timestamp(field: &'static str, value: u64) -> eros::Result<()> {
    if value == 0 {
        return Err(eros::error!(PrivilegeError::ZeroTimestamp { field }));
    }

    Ok(())
}

pub(super) fn validate_expiry(
    field: &'static str,
    checked_at_ms: u64,
    expires_at_ms: Option<u64>,
) -> eros::Result<()> {
    if let Some(expires_at_ms) = expires_at_ms
        && expires_at_ms <= checked_at_ms
    {
        return Err(eros::error!(PrivilegeError::ExpiryNotAfterCheck {
            field,
            checked_at_ms,
            expires_at_ms,
        }));
    }

    Ok(())
}

pub(super) fn validate_action_fields(
    requires_user_action: bool,
    next_action: Option<&str>,
) -> eros::Result<()> {
    match (requires_user_action, next_action) {
        (true, None) => Err(eros::error!(PrivilegeError::MissingNextAction)),
        (false, Some(_)) => Err(eros::error!(PrivilegeError::UnexpectedNextAction)),
        (_, Some(next_action)) => validate_safe_identifier("next_action", next_action),
        (_, None) => Ok(()),
    }
}
