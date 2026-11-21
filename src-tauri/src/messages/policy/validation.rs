use std::collections::HashSet;

use proto::ProtocolLimits;

use super::errors::PolicyError;
use super::types::FeaturePolicy;

pub(super) fn validate_policy_entries(
    field: &'static str,
    entries: &[FeaturePolicy],
    limits: ProtocolLimits,
) -> eros::Result<()> {
    limits.validate_batch(field, entries.len())?;

    let mut features = HashSet::with_capacity(entries.len());
    for entry in entries {
        entry.validate_with_limits(limits)?;
        if !features.insert(entry.feature.as_str()) {
            return Err(eros::error!(PolicyError::DuplicateFeature {
                field,
                feature: entry.feature.clone(),
            }));
        }
    }

    Ok(())
}

pub(super) fn validate_identifier_list(
    field: &'static str,
    values: &[String],
    limits: ProtocolLimits,
) -> eros::Result<()> {
    limits.validate_batch(field, values.len())?;

    let mut seen = HashSet::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        validate_identifier(field, Some(index), value, limits)?;
        if !seen.insert(value.as_str()) {
            return Err(eros::error!(PolicyError::DuplicateIdentifier {
                field,
                value: value.clone(),
            }));
        }
    }

    Ok(())
}

pub(super) fn validate_identifier(
    field: &'static str,
    index: Option<usize>,
    value: &str,
    limits: ProtocolLimits,
) -> eros::Result<()> {
    limits.validate_string(field, value)?;

    if value != value.trim() {
        return Err(eros::error!(PolicyError::UnexpectedWhitespace {
            field,
            index
        }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(PolicyError::ControlCharacter { field, index }));
    }
    if let Some(character) = value
        .chars()
        .find(|character| !is_identifier_character(*character))
    {
        return Err(eros::error!(PolicyError::InvalidIdentifierCharacter {
            field,
            index,
            character,
        }));
    }

    Ok(())
}

pub(super) fn is_identifier_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | ':')
}
