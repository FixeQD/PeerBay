use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::time::Duration;

use crate::protocol::{ChannelResumeCursor, ResumeRejectionReason, SessionChannel};
use crate::transport::{ChannelKind, TransportKind};

use super::state::{InvalidSessionTransition, SessionState};

mod initiator;
mod keys;
mod responder;

pub use initiator::{MigrationPlan, ResumeAcceptOutcome, TransportMigrationInitiator};
pub use keys::ResumeKeyStore;
pub use responder::{ChannelSeqSnapshot, SessionResumeOutcome, TransportMigrationResponder};

pub const MIN_HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(50);
pub const MAX_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);
pub const MIN_FALLBACK_TTL: Duration = Duration::from_millis(50);
pub const MAX_FALLBACK_TTL: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationConfig {
    pub handshake_timeout: Duration,
    pub fallback_ttl: Duration,
}

impl MigrationConfig {
    pub const fn new(handshake_timeout: Duration, fallback_ttl: Duration) -> Self {
        Self {
            handshake_timeout,
            fallback_ttl,
        }
    }

    pub fn validate(&self) -> Result<(), MigrationConfigError> {
        if self.handshake_timeout < MIN_HANDSHAKE_TIMEOUT {
            return Err(MigrationConfigError::HandshakeTimeoutTooShort {
                got: self.handshake_timeout,
                min: MIN_HANDSHAKE_TIMEOUT,
            });
        }
        if self.handshake_timeout > MAX_HANDSHAKE_TIMEOUT {
            return Err(MigrationConfigError::HandshakeTimeoutTooLong {
                got: self.handshake_timeout,
                max: MAX_HANDSHAKE_TIMEOUT,
            });
        }
        if self.fallback_ttl < MIN_FALLBACK_TTL {
            return Err(MigrationConfigError::FallbackTtlTooShort {
                got: self.fallback_ttl,
                min: MIN_FALLBACK_TTL,
            });
        }
        if self.fallback_ttl > MAX_FALLBACK_TTL {
            return Err(MigrationConfigError::FallbackTtlTooLong {
                got: self.fallback_ttl,
                max: MAX_FALLBACK_TTL,
            });
        }

        Ok(())
    }

    pub fn handshake_timeout_ms(&self) -> u64 {
        self.duration_to_ms(self.handshake_timeout)
    }

    pub fn fallback_ttl_ms(&self) -> u64 {
        self.duration_to_ms(self.fallback_ttl)
    }

    fn duration_to_ms(&self, value: Duration) -> u64 {
        value.as_millis().try_into().unwrap_or(u64::MAX)
    }
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self::new(Duration::from_secs(10), Duration::from_secs(30))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationConfigError {
    HandshakeTimeoutTooShort { got: Duration, min: Duration },
    HandshakeTimeoutTooLong { got: Duration, max: Duration },
    FallbackTtlTooShort { got: Duration, min: Duration },
    FallbackTtlTooLong { got: Duration, max: Duration },
}

impl Display for MigrationConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HandshakeTimeoutTooShort { got, min } => write!(
                formatter,
                "migration handshake timeout {got:?} is below the minimum {min:?}"
            ),
            Self::HandshakeTimeoutTooLong { got, max } => write!(
                formatter,
                "migration handshake timeout {got:?} is above the maximum {max:?}"
            ),
            Self::FallbackTtlTooShort { got, min } => write!(
                formatter,
                "migration fallback ttl {got:?} is below the minimum {min:?}"
            ),
            Self::FallbackTtlTooLong { got, max } => write!(
                formatter,
                "migration fallback ttl {got:?} is above the maximum {max:?}"
            ),
        }
    }
}

impl std::error::Error for MigrationConfigError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationFailure {
    HandshakeTimeout,
    RejectedByPeer { reason: ResumeRejectionReason },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationPhase {
    Idle,
    AwaitingAccept,
    Resumed,
    Completed,
    Failed(MigrationFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationRouteState {
    OldChannelPrimary,
    NewChannelPrimary { old_fallback_until_ms: u64 },
    Migrated,
    RolledBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationError {
    Config(MigrationConfigError),
    InvalidSessionId,
    SessionIdMismatch,
    InvalidBaseline {
        got: SessionState,
    },
    InvalidTransition(InvalidSessionTransition),
    UnexpectedPhase {
        context: &'static str,
        got: MigrationPhase,
    },
    MigrationInProgress,
    OldChannelLost,
    TargetTransportSameAsOld,
    ChannelKindMismatch,
    TransportLabelMismatch {
        expected: TransportKind,
        got: TransportKind,
    },
    ContractViolation,
    CursorMissing {
        channel: SessionChannel,
    },
    ResponseMismatch {
        field: &'static str,
    },
}

impl Display for MigrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::InvalidSessionId => {
                write!(formatter, "migration session id is not a valid identifier")
            }
            Self::SessionIdMismatch => write!(
                formatter,
                "migration session id does not match the session resume key store"
            ),
            Self::InvalidBaseline { got } => write!(
                formatter,
                "migration requires an active session state, got {got:?}"
            ),
            Self::InvalidTransition(error) => write!(formatter, "{error}"),
            Self::UnexpectedPhase { context, got } => write!(
                formatter,
                "migration call {context:?} is not allowed in phase {got:?}"
            ),
            Self::MigrationInProgress => {
                write!(formatter, "a transport migration is already in progress")
            }
            Self::OldChannelLost => write!(
                formatter,
                "migration cannot start or continue because the old channel was lost"
            ),
            Self::TargetTransportSameAsOld => write!(
                formatter,
                "migration target transport must differ from the old channel transport"
            ),
            Self::ChannelKindMismatch => {
                write!(formatter, "migrated channel must keep its channel kind")
            }
            Self::TransportLabelMismatch { expected, got } => write!(
                formatter,
                "migrated channel transport label {got:?} does not match the requested target {expected:?}"
            ),
            Self::ContractViolation => {
                write!(
                    formatter,
                    "migration contract was violated during construction"
                )
            }
            Self::CursorMissing { channel } => write!(
                formatter,
                "migration cursors do not cover the migrated channel {channel:?}"
            ),
            Self::ResponseMismatch { field } => write!(
                formatter,
                "resume response field {field} does not match the outstanding request"
            ),
        }
    }
}

impl std::error::Error for MigrationError {}

impl From<SessionChannel> for ChannelKind {
    fn from(value: SessionChannel) -> Self {
        match value {
            SessionChannel::Control => ChannelKind::Control,
            SessionChannel::Bulk => ChannelKind::Bulk,
            SessionChannel::Media => ChannelKind::Media,
            SessionChannel::Input => ChannelKind::Input,
            SessionChannel::Fallback => ChannelKind::Fallback,
        }
    }
}

pub(crate) fn transition_state(
    current: SessionState,
    next: SessionState,
) -> eros::Result<SessionState> {
    if current.can_transition(next) {
        return Ok(next);
    }

    Err(eros::error!(MigrationError::InvalidTransition(
        InvalidSessionTransition {
            from: current,
            to: next,
        }
    )))
}

pub(crate) fn require_cursor(
    cursors: &[ChannelResumeCursor],
    channel: SessionChannel,
) -> eros::Result<()> {
    if cursors.iter().any(|cursor| cursor.channel == channel) {
        return Ok(());
    }

    Err(eros::error!(MigrationError::CursorMissing { channel }))
}

pub(crate) fn cursors_cover(
    requested: &[ChannelResumeCursor],
    response: &[ChannelResumeCursor],
) -> bool {
    let echoed: HashMap<SessionChannel, (u64, u64)> = response
        .iter()
        .map(|cursor| {
            (
                cursor.channel,
                (cursor.last_received_seq, cursor.last_sent_seq),
            )
        })
        .collect();

    requested.iter().all(|cursor| {
        echoed.get(&cursor.channel) == Some(&(cursor.last_received_seq, cursor.last_sent_seq))
    })
}
