use std::env;

use super::errors::DeviceIdentityError;

pub const MAX_DEVICE_NAME_LENGTH: usize = 128;

pub fn validate_device_id(value: &str) -> eros::Result<()> {
    if value.trim().is_empty() {
        return Err(eros::error!(DeviceIdentityError::InvalidDeviceId));
    }

    let parsed = uuid::Uuid::parse_str(value)
        .map_err(|_| eros::error!(DeviceIdentityError::InvalidDeviceIdFormat))?;
    if parsed.is_nil() {
        return Err(eros::error!(DeviceIdentityError::NilDeviceId));
    }
    if parsed.to_string() != value {
        return Err(eros::error!(DeviceIdentityError::InvalidDeviceIdFormat));
    }

    Ok(())
}

pub fn validate_display_name(value: &str) -> eros::Result<()> {
    if value.trim().is_empty() {
        return Err(eros::error!(DeviceIdentityError::EmptyDisplayName));
    }
    if value != value.trim() {
        return Err(eros::error!(
            DeviceIdentityError::DisplayNameUnexpectedWhitespace
        ));
    }
    if value.len() > MAX_DEVICE_NAME_LENGTH {
        return Err(eros::error!(DeviceIdentityError::DisplayNameTooLong {
            length: value.len(),
            max: MAX_DEVICE_NAME_LENGTH,
        }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(
            DeviceIdentityError::DisplayNameControlCharacter
        ));
    }
    if value.chars().any(is_disallowed_format_character) {
        return Err(eros::error!(
            DeviceIdentityError::DisplayNameFormatCharacter
        ));
    }
    if value
        .chars()
        .any(|character| matches!(character, '\u{2028}' | '\u{2029}'))
    {
        return Err(eros::error!(DeviceIdentityError::DisplayNameLineSeparator));
    }

    Ok(())
}

fn is_disallowed_format_character(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
    )
}

pub fn default_display_name() -> String {
    env::var("HOSTNAME")
        .ok()
        .filter(|hostname| validate_display_name(hostname).is_ok())
        .unwrap_or_else(|| format!("PeerBay {}", platform_label()))
}

const fn platform_label() -> &'static str {
    if cfg!(target_os = "android") {
        "Android"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "Device"
    }
}
