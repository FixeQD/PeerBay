use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;

use crate::transport::{Transport, TransportChannel};

use super::errors::SessionError;
use super::heartbeat::Heartbeat;
use super::reconnect::ReconnectBackoff;
use super::state::{InvalidSessionTransition, SessionState};
use super::{TransportMigrationInitiator, TransportMigrationResponder};

pub const MAX_TRACKED_CHANNELS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelReleaseSummary {
    pub closed: usize,
    pub failed: usize,
    pub already_closed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseError {
    LedgerFull { tracked: usize, max: usize },
    UnknownChannel { id: String },
    SessionAlreadyClosed,
}

impl Display for ReleaseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LedgerFull { tracked, max } => write!(
                formatter,
                "session channel ledger is full: tracks {tracked} channels, cap is {max}"
            ),
            Self::UnknownChannel { id } => {
                write!(
                    formatter,
                    "session channel ledger does not track channel {id:?}"
                )
            }
            Self::SessionAlreadyClosed => {
                write!(
                    formatter,
                    "session is already closed and cannot be released again"
                )
            }
        }
    }
}

impl std::error::Error for ReleaseError {}

struct LedgerEntry {
    transport: Arc<dyn Transport>,
    channel: TransportChannel,
    closed: bool,
}

pub struct SessionChannelLedger {
    entries: Vec<LedgerEntry>,
}

impl Default for SessionChannelLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionChannelLedger {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn track(
        &mut self,
        transport: Arc<dyn Transport>,
        channel: TransportChannel,
    ) -> eros::Result<()> {
        if self.entries.len() >= MAX_TRACKED_CHANNELS {
            return Err(eros::error!(ReleaseError::LedgerFull {
                tracked: self.entries.len(),
                max: MAX_TRACKED_CHANNELS,
            }));
        }

        self.entries.push(LedgerEntry {
            transport,
            channel,
            closed: false,
        });
        Ok(())
    }

    pub fn close_channel(&mut self, channel_id: &str) -> eros::Result<bool> {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.channel.id() == channel_id)
        else {
            return Err(eros::error!(ReleaseError::UnknownChannel {
                id: channel_id.to_owned(),
            }));
        };
        if entry.closed {
            return Ok(false);
        }

        entry
            .transport
            .close(&entry.channel)
            .map_err(|error| error.context("close tracked session channel"))?;
        entry.closed = true;
        Ok(true)
    }

    pub fn close_all(&mut self) -> ChannelReleaseSummary {
        let mut summary = ChannelReleaseSummary {
            closed: 0,
            failed: 0,
            already_closed: 0,
        };
        for entry in &mut self.entries {
            if entry.closed {
                summary.already_closed += 1;
                continue;
            }
            match entry.transport.close(&entry.channel) {
                Ok(()) => {
                    entry.closed = true;
                    summary.closed += 1;
                }
                Err(_) => summary.failed += 1,
            }
        }
        summary
    }

    pub fn tracked_channels(&self) -> usize {
        self.entries.len()
    }

    pub fn open_channels(&self) -> usize {
        self.entries.iter().filter(|entry| !entry.closed).count()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn drain(&mut self) {
        self.entries.retain(|entry| !entry.closed);
    }
}

impl Debug for SessionChannelLedger {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionChannelLedger")
            .field("tracked", &self.tracked_channels())
            .field("open", &self.open_channels())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectTrigger {
    TrustRevoked,
    PolicyRevoked,
    SessionTimeout,
    HeartbeatLost,
    ProtocolViolation,
    BackendShutdown,
    PlatformServiceStopped,
    PeerReleased,
}

pub const ALL_TRIGGERS: [DisconnectTrigger; 8] = [
    DisconnectTrigger::TrustRevoked,
    DisconnectTrigger::PolicyRevoked,
    DisconnectTrigger::SessionTimeout,
    DisconnectTrigger::HeartbeatLost,
    DisconnectTrigger::ProtocolViolation,
    DisconnectTrigger::BackendShutdown,
    DisconnectTrigger::PlatformServiceStopped,
    DisconnectTrigger::PeerReleased,
];

impl DisconnectTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustRevoked => "trust_revoked",
            Self::PolicyRevoked => "policy_revoked",
            Self::SessionTimeout => "session_timeout",
            Self::HeartbeatLost => "heartbeat_lost",
            Self::ProtocolViolation => "protocol_violation",
            Self::BackendShutdown => "backend_shutdown",
            Self::PlatformServiceStopped => "platform_service_stopped",
            Self::PeerReleased => "peer_released",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::TrustRevoked
                | Self::BackendShutdown
                | Self::PeerReleased
                | Self::ProtocolViolation
        )
    }

    pub fn release_state(self, current: SessionState) -> eros::Result<SessionState> {
        if current == SessionState::Closed {
            return Err(eros::error!(ReleaseError::SessionAlreadyClosed));
        }
        if current == SessionState::Released || self.is_terminal() {
            return Ok(SessionState::Released);
        }
        if current.is_active() || current == SessionState::Reconnecting {
            return Ok(SessionState::Reconnecting);
        }
        Ok(SessionState::Disconnected)
    }
}

#[derive(Debug, Default)]
pub struct SessionResources {
    pub channels: SessionChannelLedger,
    pub initiator: Option<TransportMigrationInitiator>,
    pub responder: Option<TransportMigrationResponder>,
    pub heartbeat: Option<Heartbeat>,
    pub backoff: Option<ReconnectBackoff>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionReleaseReport {
    pub trigger: DisconnectTrigger,
    pub from_state: SessionState,
    pub to_state: SessionState,
    pub channels_closed: usize,
    pub channels_failed: usize,
    pub channels_already_closed: usize,
    pub migration_channels_closed: usize,
    pub migration_channels_failed: usize,
    pub secrets_cleared: bool,
    pub workers_stopped: usize,
    pub already_released: bool,
}

impl SessionResources {
    pub fn release(
        &mut self,
        trigger: DisconnectTrigger,
        state: &mut SessionState,
    ) -> eros::Result<SessionReleaseReport> {
        let from_state = *state;
        let mut report = SessionReleaseReport {
            trigger,
            from_state,
            to_state: from_state,
            channels_closed: 0,
            channels_failed: 0,
            channels_already_closed: 0,
            migration_channels_closed: 0,
            migration_channels_failed: 0,
            secrets_cleared: false,
            workers_stopped: 0,
            already_released: true,
        };

        if from_state == SessionState::Closed {
            return Ok(report);
        }
        report.already_released = false;

        if let Some(mut initiator) = self.initiator.take() {
            let summary = initiator.abandon();
            report.migration_channels_closed += summary.closed;
            report.migration_channels_failed += summary.failed;
        }

        if let Some(mut responder) = self.responder.take() {
            let summary = responder.teardown();
            report.migration_channels_closed += summary.closed;
            report.migration_channels_failed += summary.failed;
            report.secrets_cleared = true;
        }

        let channel_summary = self.channels.close_all();
        report.channels_closed = channel_summary.closed;
        report.channels_failed = channel_summary.failed;
        report.channels_already_closed = channel_summary.already_closed;
        self.channels.drain();

        report.workers_stopped += usize::from(self.heartbeat.take().is_some());
        report.workers_stopped += usize::from(self.backoff.take().is_some());

        let to_state = trigger.release_state(from_state)?;
        report.to_state = to_state;
        report.already_released = from_state == to_state;
        if to_state != from_state {
            if !from_state.can_transition(to_state) {
                return Err(eros::error!(SessionError::InvalidTransition(
                    InvalidSessionTransition {
                        from: from_state,
                        to: to_state,
                    }
                ))
                .context("release trigger routes session to an unreachable state"));
            }
            *state = to_state;
        }

        Ok(report)
    }
}
