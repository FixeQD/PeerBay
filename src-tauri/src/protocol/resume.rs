#![allow(dead_code)]

use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::limits::ProtocolLimits;

const RESUME_KEY_LENGTH: usize = 64;

/// A temporary, session-bound migration secret.
#[derive(Clone, PartialEq, Eq)]
pub struct ResumeKey(String);

impl ResumeKey {
    pub fn new(value: impl Into<String>) -> eros::Result<Self> {
        let key = Self(value.into());
        key.validate()?;
        Ok(key)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> eros::Result<()> {
        if self.0.len() != RESUME_KEY_LENGTH {
            return Err(eros::error!(ResumeError::InvalidKeyLength {
                length: self.0.len(),
                expected: RESUME_KEY_LENGTH,
            }));
        }
        if !self
            .0
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(eros::error!(ResumeError::InvalidKeyValue));
        }

        Ok(())
    }
}

impl Debug for ResumeKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResumeKey(<redacted>)")
    }
}

impl Serialize for ResumeKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ResumeKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|error| D::Error::custom(error.to_string()))
    }
}

/// Logical channels that can be moved to a new physical transport.
#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionChannel {
    Control,
    Bulk,
    Media,
    Input,
    Fallback,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ChannelMigration {
    pub channel: SessionChannel,
    pub old_channel_id: String,
    pub new_channel_id: String,
    pub from_transport: String,
    pub to_transport: String,
}

impl ChannelMigration {
    pub fn new(
        channel: SessionChannel,
        old_channel_id: impl Into<String>,
        new_channel_id: impl Into<String>,
        from_transport: impl Into<String>,
        to_transport: impl Into<String>,
    ) -> eros::Result<Self> {
        let migration = Self {
            channel,
            old_channel_id: old_channel_id.into(),
            new_channel_id: new_channel_id.into(),
            from_transport: from_transport.into(),
            to_transport: to_transport.into(),
        };
        migration.validate()?;
        Ok(migration)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_identifier("old_channel_id", &self.old_channel_id)?;
        validate_identifier("new_channel_id", &self.new_channel_id)?;
        validate_identifier("from_transport", &self.from_transport)?;
        validate_identifier("to_transport", &self.to_transport)?;

        if self.old_channel_id == self.new_channel_id {
            return Err(eros::error!(ResumeError::SameChannelId));
        }
        if self.from_transport == self.to_transport {
            return Err(eros::error!(ResumeError::SameTransport));
        }

        Ok(())
    }
}

/// Sequence cursors needed to continue a channel
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ChannelResumeCursor {
    pub channel: SessionChannel,
    pub last_received_seq: u64,
    pub last_sent_seq: u64,
}

impl ChannelResumeCursor {
    pub const fn new(channel: SessionChannel, last_received_seq: u64, last_sent_seq: u64) -> Self {
        Self {
            channel,
            last_received_seq,
            last_sent_seq,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SessionResumeRequest {
    pub session_id: String,
    pub resume_key: ResumeKey,
    pub migration: ChannelMigration,
    pub cursors: Vec<ChannelResumeCursor>,
    pub requested_at_ms: u64,
    pub expires_at_ms: u64,
}

impl SessionResumeRequest {
    pub fn new(
        session_id: impl Into<String>,
        resume_key: ResumeKey,
        migration: ChannelMigration,
        cursors: Vec<ChannelResumeCursor>,
        requested_at_ms: u64,
        expires_at_ms: u64,
    ) -> eros::Result<Self> {
        let request = Self {
            session_id: session_id.into(),
            resume_key,
            migration,
            cursors,
            requested_at_ms,
            expires_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_identifier("session_id", &self.session_id)?;
        self.resume_key.validate()?;
        self.migration.validate()?;
        validate_cursors(&self.cursors)?;
        validate_resume_window(self.requested_at_ms, self.expires_at_ms)?;
        Ok(())
    }

    pub fn validate_for_session(&self, envelope_session_id: &str) -> eros::Result<()> {
        self.validate()?;
        if self.session_id != envelope_session_id {
            return Err(eros::error!(ResumeError::SessionMismatch {
                expected: envelope_session_id.to_owned(),
                received: self.session_id.clone(),
            }));
        }

        Ok(())
    }

    /// Returns true at and after the key's expiry boundary.
    pub const fn is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SessionResumeAccepted {
    pub session_id: String,
    pub migration: ChannelMigration,
    pub resumed: bool,
    pub cursors: Vec<ChannelResumeCursor>,
    pub resumed_at_ms: u64,
    pub fallback_expires_at_ms: u64,
}

impl SessionResumeAccepted {
    pub fn new(
        session_id: impl Into<String>,
        migration: ChannelMigration,
        cursors: Vec<ChannelResumeCursor>,
        resumed_at_ms: u64,
        fallback_expires_at_ms: u64,
    ) -> eros::Result<Self> {
        let response = Self {
            session_id: session_id.into(),
            migration,
            resumed: true,
            cursors,
            resumed_at_ms,
            fallback_expires_at_ms,
        };
        response.validate()?;
        Ok(response)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_identifier("session_id", &self.session_id)?;
        self.migration.validate()?;
        if !self.resumed {
            return Err(eros::error!(ResumeError::AcceptedWithoutResume));
        }
        validate_cursors(&self.cursors)?;
        if self.resumed_at_ms == 0 {
            return Err(eros::error!(ResumeError::ZeroTimestamp {
                field: "resumed_at_ms",
            }));
        }
        if self.fallback_expires_at_ms <= self.resumed_at_ms {
            return Err(eros::error!(ResumeError::FallbackExpiryNotAfterResume));
        }

        Ok(())
    }

    pub const fn fallback_is_expired_at(&self, now_ms: u64) -> bool {
        now_ms >= self.fallback_expires_at_ms
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeRejectionReason {
    InvalidResumeKey,
    ExpiredResumeKey,
    SessionMismatch,
    ChannelAlreadyActive,
    UnknownChannel,
    SequenceConflict,
    TransportUnavailable,
    ProtocolViolation,
    Unauthorized,
    PeerUnavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SessionResumeRejected {
    pub session_id: String,
    pub reason: ResumeRejectionReason,
    pub retryable: bool,
}

impl SessionResumeRejected {
    pub fn new(
        session_id: impl Into<String>,
        reason: ResumeRejectionReason,
        retryable: bool,
    ) -> eros::Result<Self> {
        let response = Self {
            session_id: session_id.into(),
            reason,
            retryable,
        };
        response.validate()?;
        Ok(response)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_identifier("session_id", &self.session_id)
    }
}

fn validate_resume_window(requested_at_ms: u64, expires_at_ms: u64) -> eros::Result<()> {
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

fn validate_cursors(cursors: &[ChannelResumeCursor]) -> eros::Result<()> {
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

fn validate_identifier(field: &'static str, value: &str) -> eros::Result<()> {
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

#[derive(Debug, PartialEq, Eq)]
pub enum ResumeError {
    InvalidKeyLength {
        length: usize,
        expected: usize,
    },
    InvalidKeyValue,
    SameChannelId,
    SameTransport,
    EmptyCursors,
    DuplicateChannel {
        channel: SessionChannel,
    },
    SessionMismatch {
        expected: String,
        received: String,
    },
    ZeroTimestamp {
        field: &'static str,
    },
    ExpiryNotAfterRequest {
        requested_at_ms: u64,
        expires_at_ms: u64,
    },
    AcceptedWithoutResume,
    FallbackExpiryNotAfterResume,
    UnexpectedWhitespace {
        field: &'static str,
    },
    ControlCharacter {
        field: &'static str,
    },
    InvalidIdentifierCharacter {
        field: &'static str,
    },
}

impl Display for ResumeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength { length, expected } => write!(
                formatter,
                "resume key has {length} characters; expected {expected}"
            ),
            Self::InvalidKeyValue => {
                write!(formatter, "resume key must be canonical lowercase hex")
            }
            Self::SameChannelId => write!(formatter, "channel migration must change channel ID"),
            Self::SameTransport => write!(formatter, "channel migration must change transport"),
            Self::EmptyCursors => {
                write!(formatter, "resume must include at least one channel cursor")
            }
            Self::DuplicateChannel { channel } => {
                write!(
                    formatter,
                    "resume contains duplicate cursor for {channel:?}"
                )
            }
            Self::SessionMismatch { expected, received } => write!(
                formatter,
                "resume session mismatch: expected {expected}, received {received}"
            ),
            Self::ZeroTimestamp { field } => {
                write!(
                    formatter,
                    "resume timestamp {field} must be greater than zero"
                )
            }
            Self::ExpiryNotAfterRequest {
                requested_at_ms,
                expires_at_ms,
            } => write!(
                formatter,
                "resume expiry {expires_at_ms} must be after request time {requested_at_ms}"
            ),
            Self::AcceptedWithoutResume => {
                write!(formatter, "accepted resume response must set resumed=true")
            }
            Self::FallbackExpiryNotAfterResume => write!(
                formatter,
                "fallback expiry must be after the resumed timestamp"
            ),
            Self::UnexpectedWhitespace { field } => {
                write!(
                    formatter,
                    "resume field {field} has unexpected surrounding whitespace"
                )
            }
            Self::ControlCharacter { field } => {
                write!(
                    formatter,
                    "resume field {field} contains a control character"
                )
            }
            Self::InvalidIdentifierCharacter { field } => write!(
                formatter,
                "resume field {field} contains an invalid identifier character"
            ),
        }
    }
}

impl std::error::Error for ResumeError {}
