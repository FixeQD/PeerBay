#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use super::limits::ProtocolLimits;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CapabilityDocument {
    pub platform: String,
    pub platform_version: String,
    pub protocol_versions: Vec<u16>,
    pub transports: Vec<String>,
    pub features: Vec<String>,
    pub codecs: Vec<String>,
    pub max_file_size: u64,
    pub max_message_size: u64,
    pub input_modes: Vec<String>,
    pub screen_modes: Vec<String>,
    pub audio_modes: Vec<String>,
    pub permissions: Vec<String>,
}

impl CapabilityDocument {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        platform: impl Into<String>,
        platform_version: impl Into<String>,
        protocol_versions: Vec<u16>,
        transports: Vec<String>,
        features: Vec<String>,
        codecs: Vec<String>,
        max_file_size: u64,
        max_message_size: u64,
        input_modes: Vec<String>,
        screen_modes: Vec<String>,
        audio_modes: Vec<String>,
        permissions: Vec<String>,
    ) -> eros::Result<Self> {
        let document = Self {
            platform: platform.into(),
            platform_version: platform_version.into(),
            protocol_versions,
            transports,
            features,
            codecs,
            max_file_size,
            max_message_size,
            input_modes,
            screen_modes,
            audio_modes,
            permissions,
        };

        document.validate()?;
        Ok(document)
    }

    pub fn validate(&self) -> eros::Result<()> {
        self.validate_with_limits(ProtocolLimits::default())
    }

    pub fn validate_with_limits(&self, limits: ProtocolLimits) -> eros::Result<()> {
        validate_string("platform", None, &self.platform, limits)?;
        validate_string("platform_version", None, &self.platform_version, limits)?;

        if self.protocol_versions.is_empty() {
            return Err(eros::error!(CapabilityError::EmptyList {
                field: "protocol_versions",
            }));
        }

        limits.validate_batch("protocol_versions", self.protocol_versions.len())?;
        for version in &self.protocol_versions {
            if *version == 0 {
                return Err(eros::error!(CapabilityError::InvalidProtocolVersion {
                    version: *version,
                }));
            }
        }
        reject_duplicate_protocol_versions(&self.protocol_versions)?;

        validate_identifier_list("transports", &self.transports, limits)?;
        validate_identifier_list("features", &self.features, limits)?;
        validate_identifier_list("codecs", &self.codecs, limits)?;
        validate_identifier_list("input_modes", &self.input_modes, limits)?;
        validate_identifier_list("screen_modes", &self.screen_modes, limits)?;
        validate_identifier_list("audio_modes", &self.audio_modes, limits)?;
        validate_identifier_list("permissions", &self.permissions, limits)?;

        if self.max_file_size == 0 {
            return Err(eros::error!(CapabilityError::ZeroLimit {
                field: "max_file_size",
            }));
        }
        if self.max_message_size == 0 {
            return Err(eros::error!(CapabilityError::ZeroLimit {
                field: "max_message_size",
            }));
        }

        Ok(())
    }

    pub fn supports_protocol_version(&self, version: u16) -> bool {
        self.protocol_versions.contains(&version)
    }

    pub fn supports_transport(&self, transport: &str) -> bool {
        self.transports.iter().any(|value| value == transport)
    }

    pub fn supports_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|value| value == feature)
    }

    pub fn supports_codec(&self, codec: &str) -> bool {
        self.codecs.iter().any(|value| value == codec)
    }

    pub fn negotiate(&self, peer: &Self) -> eros::Result<NegotiatedCapabilities> {
        self.validate()?;
        peer.validate()?;

        let protocol_version = self
            .protocol_versions
            .iter()
            .copied()
            .filter(|version| peer.protocol_versions.contains(version))
            .max()
            .ok_or_else(|| eros::error!(CapabilityError::NoCommonProtocolVersion))?;

        Ok(NegotiatedCapabilities {
            protocol_version,
            transports: intersect(&self.transports, &peer.transports),
            features: intersect(&self.features, &peer.features),
            codecs: intersect(&self.codecs, &peer.codecs),
            max_file_size: self.max_file_size.min(peer.max_file_size),
            max_message_size: self.max_message_size.min(peer.max_message_size),
            input_modes: intersect(&self.input_modes, &peer.input_modes),
            screen_modes: intersect(&self.screen_modes, &peer.screen_modes),
            audio_modes: intersect(&self.audio_modes, &peer.audio_modes),
            permissions: intersect(&self.permissions, &peer.permissions),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NegotiatedCapabilities {
    pub protocol_version: u16,
    pub transports: Vec<String>,
    pub features: Vec<String>,
    pub codecs: Vec<String>,
    pub max_file_size: u64,
    pub max_message_size: u64,
    pub input_modes: Vec<String>,
    pub screen_modes: Vec<String>,
    pub audio_modes: Vec<String>,
    pub permissions: Vec<String>,
}

impl NegotiatedCapabilities {
    pub fn supports_transport(&self, transport: &str) -> bool {
        self.transports.iter().any(|value| value == transport)
    }

    pub fn supports_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|value| value == feature)
    }

    pub fn supports_codec(&self, codec: &str) -> bool {
        self.codecs.iter().any(|value| value == codec)
    }
}

fn validate_identifier_list(
    field: &'static str,
    values: &[String],
    limits: ProtocolLimits,
) -> eros::Result<()> {
    limits.validate_batch(field, values.len())?;

    let mut seen = HashSet::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        validate_string(field, Some(index), value, limits)?;
        if !seen.insert(value.as_str()) {
            return Err(eros::error!(CapabilityError::DuplicateValue {
                field,
                value: value.clone(),
            }));
        }
    }

    Ok(())
}

fn validate_string(
    field: &'static str,
    index: Option<usize>,
    value: &str,
    limits: ProtocolLimits,
) -> eros::Result<()> {
    limits.validate_string(field, value)?;

    if value != value.trim() {
        return Err(eros::error!(CapabilityError::UnexpectedWhitespace {
            field,
            index
        }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(CapabilityError::ControlCharacter {
            field,
            index
        }));
    }

    Ok(())
}

fn reject_duplicate_protocol_versions(versions: &[u16]) -> eros::Result<()> {
    let mut seen = HashSet::with_capacity(versions.len());
    for version in versions {
        if !seen.insert(version) {
            return Err(eros::error!(CapabilityError::DuplicateProtocolVersion {
                version: *version,
            }));
        }
    }

    Ok(())
}

fn intersect(local: &[String], peer: &[String]) -> Vec<String> {
    local
        .iter()
        .filter(|value| peer.iter().any(|peer_value| peer_value == *value))
        .cloned()
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapabilityError {
    EmptyList {
        field: &'static str,
    },
    InvalidProtocolVersion {
        version: u16,
    },
    DuplicateProtocolVersion {
        version: u16,
    },
    DuplicateValue {
        field: &'static str,
        value: String,
    },
    UnexpectedWhitespace {
        field: &'static str,
        index: Option<usize>,
    },
    ControlCharacter {
        field: &'static str,
        index: Option<usize>,
    },
    ZeroLimit {
        field: &'static str,
    },
    NoCommonProtocolVersion,
}

impl Display for CapabilityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyList { field } => {
                write!(formatter, "capability list {field} must not be empty")
            }
            Self::InvalidProtocolVersion { version } => {
                write!(formatter, "protocol version {version} is invalid")
            }
            Self::DuplicateProtocolVersion { version } => {
                write!(formatter, "protocol version {version} is duplicated")
            }
            Self::DuplicateValue { field, value } => {
                write!(
                    formatter,
                    "capability {field} contains duplicate value {value}"
                )
            }
            Self::UnexpectedWhitespace { field, index } => {
                write!(
                    formatter,
                    "capability field {field}{index_suffix} has unexpected surrounding whitespace",
                    index_suffix = format_index(*index)
                )
            }
            Self::ControlCharacter { field, index } => {
                write!(
                    formatter,
                    "capability field {field}{index_suffix} contains a control character",
                    index_suffix = format_index(*index)
                )
            }
            Self::ZeroLimit { field } => {
                write!(
                    formatter,
                    "capability limit {field} must be greater than zero"
                )
            }
            Self::NoCommonProtocolVersion => {
                write!(
                    formatter,
                    "capability documents have no common protocol version"
                )
            }
        }
    }
}

fn format_index(index: Option<usize>) -> String {
    index.map_or_else(String::new, |index| format!("[{index}]"))
}

impl std::error::Error for CapabilityError {}
