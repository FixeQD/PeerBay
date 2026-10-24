#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use super::limits::ProtocolLimits;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserPolicyState {
    Unset,
    Allow,
    Deny,
    Ask,
    AllowLimited,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FeaturePolicy {
    pub feature: String,
    pub state: UserPolicyState,
    pub limitations: Vec<String>,
    pub max_bytes: Option<u64>,
    pub expires_at_ms: Option<u64>,
}

impl FeaturePolicy {
    pub fn new(
        feature: impl Into<String>,
        state: UserPolicyState,
        limitations: Vec<String>,
        max_bytes: Option<u64>,
        expires_at_ms: Option<u64>,
    ) -> eros::Result<Self> {
        let policy = Self {
            feature: feature.into(),
            state,
            limitations,
            max_bytes,
            expires_at_ms,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> eros::Result<()> {
        self.validate_with_limits(ProtocolLimits::default())
    }

    pub fn validate_with_limits(&self, limits: ProtocolLimits) -> eros::Result<()> {
        validate_identifier("feature", None, &self.feature, limits)?;
        validate_identifier_list("limitations", &self.limitations, limits)?;

        let has_restriction = !self.limitations.is_empty() || self.max_bytes.is_some();
        if has_restriction && self.state != UserPolicyState::AllowLimited {
            return Err(eros::error!(PolicyError::RestrictionsRequireLimitedState {
                feature: self.feature.clone(),
            }));
        }

        if self.state == UserPolicyState::AllowLimited && !has_restriction {
            return Err(eros::error!(PolicyError::LimitedStateRequiresRestriction {
                feature: self.feature.clone(),
            }));
        }

        if self.state == UserPolicyState::Unset && self.expires_at_ms.is_some() {
            return Err(eros::error!(PolicyError::ExpiryNotAllowedForUnset {
                feature: self.feature.clone(),
            }));
        }

        if self.max_bytes == Some(0) {
            return Err(eros::error!(PolicyError::ZeroMaxBytes {
                feature: self.feature.clone(),
            }));
        }

        if self.expires_at_ms == Some(0) {
            return Err(eros::error!(PolicyError::ZeroExpiry {
                feature: self.feature.clone(),
            }));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PolicyGetRequest {
    pub features: Vec<String>,
}

impl PolicyGetRequest {
    pub fn all() -> Self {
        Self {
            features: Vec::new(),
        }
    }

    pub fn for_features(features: Vec<String>) -> eros::Result<Self> {
        let request = Self { features };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_identifier_list("features", &self.features, ProtocolLimits::default())
    }

    pub fn validate_with_limits(&self, limits: ProtocolLimits) -> eros::Result<()> {
        validate_identifier_list("features", &self.features, limits)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PolicyGetResponse {
    pub revision: u64,
    pub policies: Vec<FeaturePolicy>,
}

impl PolicyGetResponse {
    pub fn new(revision: u64, policies: Vec<FeaturePolicy>) -> eros::Result<Self> {
        let response = Self { revision, policies };
        response.validate()?;
        Ok(response)
    }

    pub fn validate(&self) -> eros::Result<()> {
        self.validate_with_limits(ProtocolLimits::default())
    }

    pub fn validate_with_limits(&self, limits: ProtocolLimits) -> eros::Result<()> {
        validate_policy_entries("policies", &self.policies, limits)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PolicySetRequest {
    /// Revision observed by the caller
    pub base_revision: u64,
    pub changes: Vec<FeaturePolicy>,
}

impl PolicySetRequest {
    pub fn new(base_revision: u64, changes: Vec<FeaturePolicy>) -> eros::Result<Self> {
        let request = Self {
            base_revision,
            changes,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> eros::Result<()> {
        self.validate_with_limits(ProtocolLimits::default())
    }

    pub fn validate_with_limits(&self, limits: ProtocolLimits) -> eros::Result<()> {
        if self.changes.is_empty() {
            return Err(eros::error!(PolicyError::EmptyChanges));
        }

        validate_policy_entries("changes", &self.changes, limits)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRejectionReason {
    UnknownFeature,
    InvalidChange,
    RevisionConflict,
    Unauthorized,
    CapabilityUnavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PolicyRejection {
    pub feature: String,
    pub reason: PolicyRejectionReason,
    pub limitations: Vec<String>,
}

impl PolicyRejection {
    pub fn new(
        feature: impl Into<String>,
        reason: PolicyRejectionReason,
        limitations: Vec<String>,
    ) -> eros::Result<Self> {
        let rejection = Self {
            feature: feature.into(),
            reason,
            limitations,
        };
        rejection.validate()?;
        Ok(rejection)
    }

    pub fn validate(&self) -> eros::Result<()> {
        self.validate_with_limits(ProtocolLimits::default())
    }

    pub fn validate_with_limits(&self, limits: ProtocolLimits) -> eros::Result<()> {
        validate_identifier("feature", None, &self.feature, limits)?;
        validate_identifier_list("limitations", &self.limitations, limits)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PolicySetResponse {
    pub revision: u64,
    pub applied: Vec<FeaturePolicy>,
    pub rejected: Vec<PolicyRejection>,
}

impl PolicySetResponse {
    pub fn new(
        revision: u64,
        applied: Vec<FeaturePolicy>,
        rejected: Vec<PolicyRejection>,
    ) -> eros::Result<Self> {
        let response = Self {
            revision,
            applied,
            rejected,
        };
        response.validate()?;
        Ok(response)
    }

    pub fn validate(&self) -> eros::Result<()> {
        self.validate_with_limits(ProtocolLimits::default())
    }

    pub fn validate_with_limits(&self, limits: ProtocolLimits) -> eros::Result<()> {
        if self.applied.is_empty() && self.rejected.is_empty() {
            return Err(eros::error!(PolicyError::EmptySetResponse));
        }

        for policy in &self.applied {
            policy.validate_with_limits(limits)?;
        }
        for rejection in &self.rejected {
            rejection.validate_with_limits(limits)?;
        }

        let mut features = HashSet::with_capacity(self.applied.len() + self.rejected.len());
        for policy in &self.applied {
            if !features.insert(policy.feature.as_str()) {
                return Err(eros::error!(PolicyError::DuplicateFeature {
                    field: "applied",
                    feature: policy.feature.clone(),
                }));
            }
        }
        for rejection in &self.rejected {
            if !features.insert(rejection.feature.as_str()) {
                return Err(eros::error!(PolicyError::DuplicateFeature {
                    field: "rejected",
                    feature: rejection.feature.clone(),
                }));
            }
        }

        Ok(())
    }
}

fn validate_policy_entries(
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

fn validate_identifier_list(
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

fn validate_identifier(
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

fn is_identifier_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | ':')
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    EmptyChanges,
    EmptySetResponse,
    DuplicateFeature {
        field: &'static str,
        feature: String,
    },
    DuplicateIdentifier {
        field: &'static str,
        value: String,
    },
    RestrictionsRequireLimitedState {
        feature: String,
    },
    LimitedStateRequiresRestriction {
        feature: String,
    },
    ExpiryNotAllowedForUnset {
        feature: String,
    },
    ZeroMaxBytes {
        feature: String,
    },
    ZeroExpiry {
        feature: String,
    },
    UnexpectedWhitespace {
        field: &'static str,
        index: Option<usize>,
    },
    ControlCharacter {
        field: &'static str,
        index: Option<usize>,
    },
    InvalidIdentifierCharacter {
        field: &'static str,
        index: Option<usize>,
        character: char,
    },
}

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyChanges => write!(formatter, "policy.set must contain at least one change"),
            Self::EmptySetResponse => write!(
                formatter,
                "policy.set response must contain an applied or rejected feature"
            ),
            Self::DuplicateFeature { field, feature } => {
                write!(
                    formatter,
                    "policy {field} contains duplicate feature {feature}"
                )
            }
            Self::DuplicateIdentifier { field, value } => {
                write!(
                    formatter,
                    "policy {field} contains duplicate identifier {value}"
                )
            }
            Self::RestrictionsRequireLimitedState { feature } => write!(
                formatter,
                "policy {feature} must use allow_limited when restrictions are present"
            ),
            Self::LimitedStateRequiresRestriction { feature } => write!(
                formatter,
                "allow_limited policy {feature} must declare a restriction"
            ),
            Self::ExpiryNotAllowedForUnset { feature } => write!(
                formatter,
                "unset policy {feature} must not declare an expiry"
            ),
            Self::ZeroMaxBytes { feature } => {
                write!(
                    formatter,
                    "policy {feature} max_bytes must be greater than zero"
                )
            }
            Self::ZeroExpiry { feature } => {
                write!(
                    formatter,
                    "policy {feature} expiry must be greater than zero"
                )
            }
            Self::UnexpectedWhitespace { field, index } => write!(
                formatter,
                "policy field {field}{} has unexpected surrounding whitespace",
                format_index(*index)
            ),
            Self::ControlCharacter { field, index } => write!(
                formatter,
                "policy field {field}{} contains a control character",
                format_index(*index)
            ),
            Self::InvalidIdentifierCharacter {
                field,
                index,
                character,
            } => write!(
                formatter,
                "policy field {field}{} contains invalid identifier character {character:?}",
                format_index(*index)
            ),
        }
    }
}

fn format_index(index: Option<usize>) -> String {
    index.map_or_else(String::new, |index| format!("[{index}]"))
}

impl std::error::Error for PolicyError {}
