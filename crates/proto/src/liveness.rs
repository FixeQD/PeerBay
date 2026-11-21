use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

use super::limits::ProtocolLimits;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct PingBody {}

impl PingBody {
    pub fn new() -> Self {
        Self {}
    }

    pub fn validate(&self) -> eros::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PongBody {
    pub ping_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ping_seq: Option<u64>,
}

impl PongBody {
    pub fn new(ping_id: impl Into<String>, ping_seq: Option<u64>) -> eros::Result<Self> {
        let body = Self {
            ping_id: ping_id.into(),
            ping_seq,
        };
        body.validate()?;
        Ok(body)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_identifier("ping_id", &self.ping_id)
    }
}

fn validate_identifier(field: &'static str, value: &str) -> eros::Result<()> {
    let limits = ProtocolLimits::default();
    limits.validate_string(field, value)?;

    if value != value.trim() {
        return Err(eros::error!(LivenessError::UnexpectedWhitespace { field }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(LivenessError::ControlCharacter { field }));
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LivenessError {
    UnexpectedWhitespace { field: &'static str },
    ControlCharacter { field: &'static str },
}

impl Display for LivenessError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedWhitespace { field } => {
                write!(
                    formatter,
                    "liveness field {field} has unexpected surrounding whitespace"
                )
            }
            Self::ControlCharacter { field } => {
                write!(
                    formatter,
                    "liveness field {field} contains a control character"
                )
            }
        }
    }
}

impl std::error::Error for LivenessError {}

impl<'de> Deserialize<'de> for PongBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawPongBody {
            ping_id: String,
            #[serde(default)]
            ping_seq: Option<u64>,
        }

        let raw = RawPongBody::deserialize(deserializer)?;
        let body = Self {
            ping_id: raw.ping_id,
            ping_seq: raw.ping_seq,
        };
        body.validate()
            .map_err(|error| serde::de::Error::custom(error.to_string()))?;
        Ok(body)
    }
}
