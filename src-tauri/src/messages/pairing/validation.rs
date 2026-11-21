use std::collections::HashSet;

use proto::ProtocolLimits;

use super::errors::PairingError;

pub(super) const HEX_256_LENGTH: usize = 64;
pub(super) const SAS_CODE_LENGTH: usize = 6;

pub(super) fn validate_pairing_id(value: &str) -> eros::Result<()> {
    validate_identifier("pairing_id", value)
}

pub(super) fn validate_identifier(field: &'static str, value: &str) -> eros::Result<()> {
    let limits = ProtocolLimits::default();
    limits.validate_string(field, value)?;

    if value != value.trim() {
        return Err(eros::error!(PairingError::UnexpectedWhitespace { field }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(PairingError::ControlCharacter { field }));
    }
    if value.chars().any(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-' | ':')
    }) {
        return Err(eros::error!(PairingError::InvalidIdentifierCharacter {
            field
        }));
    }

    Ok(())
}

pub(super) fn validate_hex_256(field: &'static str, value: &str) -> eros::Result<()> {
    if value.len() != HEX_256_LENGTH {
        return Err(eros::error!(PairingError::InvalidHexLength {
            field,
            length: value.len(),
            expected: HEX_256_LENGTH,
        }));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(eros::error!(PairingError::InvalidHexValue { field }));
    }

    Ok(())
}

pub(super) fn validate_sas_code(value: &str) -> eros::Result<()> {
    if value.len() != SAS_CODE_LENGTH {
        return Err(eros::error!(PairingError::InvalidSasCodeLength {
            length: value.len(),
            expected: SAS_CODE_LENGTH,
        }));
    }
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(eros::error!(PairingError::InvalidSasCodeValue));
    }

    Ok(())
}

pub(super) fn validate_expiry(expires_at_ms: u64) -> eros::Result<()> {
    if expires_at_ms == 0 {
        return Err(eros::error!(PairingError::ZeroExpiry));
    }
    Ok(())
}

pub(super) fn validate_protocol_versions(versions: &[u16]) -> eros::Result<()> {
    let limits = ProtocolLimits::default();
    if versions.is_empty() {
        return Err(eros::error!(PairingError::EmptyProtocolVersions));
    }
    limits.validate_batch("protocol_versions", versions.len())?;

    let mut seen = HashSet::with_capacity(versions.len());
    for version in versions {
        if *version == 0 {
            return Err(eros::error!(PairingError::InvalidProtocolVersion {
                version: *version
            }));
        }
        if !seen.insert(version) {
            return Err(eros::error!(PairingError::DuplicateProtocolVersion {
                version: *version
            }));
        }
    }

    Ok(())
}
