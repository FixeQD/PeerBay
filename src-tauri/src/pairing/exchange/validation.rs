use crate::pairing::PairingExchangeError;
use crate::protocol::limits::ProtocolLimits;

pub(super) const MAX_PAIRING_ID_LENGTH: usize = 128;
pub(super) const MAX_DEVICE_ID_LENGTH: usize = 128;
pub(super) const MAX_CERTIFICATE_FINGERPRINT_LENGTH: usize = 128;
pub(super) const MAX_PROTOCOL_VERSION_COUNT: usize = 64;

pub(super) fn limits() -> ProtocolLimits {
    ProtocolLimits::default()
}

pub(super) fn is_lower_hex(value: &str, length: usize) -> bool {
    if length == 0 || value.len() != length {
        return false;
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn parse_pairing_id(value: &str) -> Result<(), PairingExchangeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(PairingExchangeError::InvalidPairingId);
    }
    if value.chars().any(char::is_control) {
        return Err(PairingExchangeError::InvalidPairingId);
    }
    if value.len() > MAX_PAIRING_ID_LENGTH {
        return Err(PairingExchangeError::InvalidPairingId);
    }
    if value.chars().any(|character| {
        character.is_ascii_whitespace()
            || !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | ':'))
    }) {
        return Err(PairingExchangeError::InvalidPairingId);
    }
    if limits().validate_string("pairing_id", value).is_err() {
        return Err(PairingExchangeError::InvalidPairingId);
    }

    Ok(())
}

pub(super) fn validate_device_id(value: &str) -> Result<(), PairingExchangeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(PairingExchangeError::InvalidDeviceId);
    }
    if value.chars().any(char::is_control) {
        return Err(PairingExchangeError::InvalidDeviceId);
    }
    if value.len() > MAX_DEVICE_ID_LENGTH {
        return Err(PairingExchangeError::InvalidDeviceId);
    }
    if value
        .chars()
        .any(|character| character.is_ascii_whitespace())
    {
        return Err(PairingExchangeError::InvalidDeviceId);
    }
    if limits().validate_string("device_id", value).is_err() {
        return Err(PairingExchangeError::InvalidDeviceId);
    }

    Ok(())
}

pub(super) fn validate_fingerprint(value: &str) -> Result<(), PairingExchangeError> {
    if value.is_empty() {
        return Err(PairingExchangeError::InvalidCertificateFingerprint);
    }
    if value.len() > MAX_CERTIFICATE_FINGERPRINT_LENGTH {
        return Err(PairingExchangeError::InvalidCertificateFingerprint);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'-' | b'_'))
    {
        return Err(PairingExchangeError::InvalidCertificateFingerprint);
    }

    Ok(())
}

pub(super) fn validate_fingerprint_hex(value: &str) -> Result<(), PairingExchangeError> {
    if !is_lower_hex(value, 64) {
        return Err(PairingExchangeError::InvalidCertificateFingerprint);
    }
    Ok(())
}

pub(super) fn validate_protocol_versions(versions: &[u16]) -> Result<(), PairingExchangeError> {
    if versions.is_empty() || versions.len() > MAX_PROTOCOL_VERSION_COUNT {
        return Err(PairingExchangeError::InvalidProtocolVersions);
    }
    let mut seen = std::collections::BTreeSet::new();
    for version in versions {
        if *version == 0 || !seen.insert(version) {
            return Err(PairingExchangeError::InvalidProtocolVersions);
        }
    }
    if limits()
        .validate_batch("protocol_versions", versions.len())
        .is_err()
    {
        return Err(PairingExchangeError::InvalidProtocolVersions);
    }

    Ok(())
}
